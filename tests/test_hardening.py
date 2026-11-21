"""Tests for five small hardening fixes: the checksum check in
multiupload/finish, re-uploads through upload/file, HTML escaping, the raw
log's content type, and role values in mod/team/update.

    python tests/test_hardening.py

See tests/common.py for what is needed to run them.
"""
import os
import unittest
from unittest import mock

import pygments.formatters
from flask import render_template

from common import (
    Base, PublishedFile, UPLOADS, app, client, create_mod, finish, make_user, models, release,
    send_chunks, sha, stored_tree, upload_chunked, upload_small
)


class FinishChecksumFormat(Base):
    """multiupload/finish refuses a checksum that is not 64 lowercase hex
    characters, before it makes a record or a path from it."""

    BAD_VALUES = ['', 'short', 'g' * 64, 'a' * 63, 'a' * 65, 'A' * 64,
                  'aa/' + 'a' * 61, 'a' * 64 + '\n']

    def test_malformed_checksum_is_refused(self):
        headers = make_user('alice')
        for number, value in enumerate(self.BAD_VALUES):
            with self.subTest(value=value):
                upload_id = '%016x' % number
                send_chunks(headers, upload_id, b'some archive bytes')
                before = stored_tree()
                with mock.patch.object(models.UploadedFile, 'save') as save:
                    resp = finish(headers, upload_id, value)
                self.assertFalse(save.called)
                self.assertEqual(stored_tree(), before)
                self.assertEqual(models.UploadedFile.objects.count(), 0)
                self.assertEqual(resp.status_code, 400)

    def test_format_is_checked_before_anything_is_looked_up(self):
        headers = make_user('alice')
        resp = finish(headers, 'ff' * 8, 'short')
        self.assertEqual(resp.status_code, 400)
        resp = finish(headers, 'ff' * 8, 'a' * 64)
        self.assertEqual(resp.status_code, 404)

    def test_missing_checksum_is_refused(self):
        headers = make_user('alice')
        send_chunks(headers, 'ab' * 8, b'abc')
        resp = client.post('/api/1/multiupload/finish', headers=headers, data={'id': 'ab' * 8})
        self.assertEqual(resp.status_code, 400)

    def test_valid_checksum_still_works(self):
        headers = make_user('alice')
        data = b'some archive bytes'
        resp = upload_chunked(headers, 'cd' * 8, data, sha(data))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {'result': True})
        self.assertEqual(models.UploadedFile.objects(checksum=sha(data)).first().expires, -1)

    def test_wrong_but_well_formed_checksum_still_fails_cleanly(self):
        headers = make_user('alice')
        send_chunks(headers, 'ef' * 8, b'some archive bytes')
        before = stored_tree()
        resp = finish(headers, 'ef' * 8, sha(b'other bytes'))
        self.assertEqual(resp.get_json(), {'result': False, 'reason': 'checksum fail'})
        self.assertEqual(models.UploadedFile.objects.count(), 0)
        self.assertEqual(stored_tree(), before)


class SecondPlainUpload(PublishedFile):
    """upload/file leaves the record of a permanent file alone, and only that."""

    def test_published_file_sent_again(self):
        headers = make_user('carol')
        data = b'published archive bytes'
        self.publish(headers, data)
        resp = upload_small(headers, data)
        self.assert_still_published(data)
        self.assertEqual(resp.get_json(), {'result': True})

    def test_other_bytes_under_a_published_checksum_are_still_refused(self):
        headers = make_user('carol')
        data = b'published archive bytes'
        self.publish(headers, data)
        resp = upload_small(headers, b'something else entirely', checksum=sha(data))
        self.assertEqual(resp.get_json(), {'result': False, 'reason': 'checksum'})
        self.assert_still_published(data)

    def test_unreleased_file_whose_temp_copy_is_gone_is_stored_again(self):
        # A request that died between saving the record and saving the file
        # leaves this state; the client's retry has to be able to repair it.
        headers = make_user('carol')
        data = b'not released yet'
        upload_small(headers, data)
        record = models.UploadedFile.objects(checksum=sha(data)).first()
        self.assertNotEqual(record.expires, -1)
        os.unlink(os.path.join(UPLOADS, record.filename))

        resp = upload_small(headers, data)
        self.assertEqual(resp.get_json(), {'result': True})
        with open(os.path.join(UPLOADS, record.filename), 'rb') as stream:
            self.assertEqual(stream.read(), data)
        create_mod(headers, 'latemod')
        self.assertTrue(release(headers, 'latemod', '1.0.0', sha(data)).get_json()['result'])

    def test_published_file_missing_from_disk_is_not_restored(self):
        # A known cost, not a goal: the record is all that is looked at.
        # Change this test with the behaviour.
        headers = make_user('carol')
        data = b'published archive bytes'
        self.publish(headers, data)
        record = models.UploadedFile.objects(checksum=sha(data)).first()
        os.unlink(os.path.join(UPLOADS, record.filename))

        resp = upload_small(headers, data)
        self.assertEqual(resp.get_json(), {'result': True})
        self.assertEqual(models.UploadedFile.objects(checksum=sha(data)).first().expires, -1)
        self.assertFalse(os.path.exists(os.path.join(UPLOADS, record.filename)))


class TemplateEscaping(Base):
    """HTML pages escape what users typed; plain-text mail does not."""

    TITLE = '<b>T&C</b> "quoted" \'single\''
    PKG = '<u>pkg</u> "name"'
    NOTES = '<i>notes</i> "said"'
    ARCHIVE = '<s>a</s>".7z'

    def make_release(self):
        headers = make_user('erin')
        data = b'archive'
        upload_small(headers, data)
        create_mod(headers, 'escmod', title=self.TITLE)
        resp = release(headers, 'escmod', '1.0.0', sha(data), pkg_name=self.PKG,
                       notes=self.NOTES, archive_name=self.ARCHIVE)
        self.assertTrue(resp.get_json()['result'])

    def assert_escaped(self, page, *raw_values):
        for raw in raw_values:
            with self.subTest(raw=raw):
                self.assertNotIn(raw, page)
                self.assertNotIn(raw.split(' ')[0], page)

    def test_mod_pages(self):
        self.make_release()

        listing = client.get('/mods').get_data(as_text=True)
        self.assertIn('&lt;b&gt;T&amp;C&lt;/b&gt;', listing)
        self.assert_escaped(listing, self.TITLE)

        page = client.get('/mod/escmod').get_data(as_text=True)
        self.assertIn('&lt;b&gt;T&amp;C&lt;/b&gt;', page)
        self.assertIn('&lt;u&gt;pkg&lt;/u&gt;', page)
        self.assertIn('&lt;i&gt;notes&lt;/i&gt;', page)
        self.assertIn('&lt;s&gt;a&lt;/s&gt;', page)
        self.assert_escaped(page, self.TITLE, self.PKG, self.NOTES, self.ARCHIVE)
        # The archive name is also part of a download link's address.
        self.assertNotIn('".7z"', page)

        versions = client.get('/mod/escmod/all').get_data(as_text=True)
        self.assertIn('&lt;b&gt;T&amp;C&lt;/b&gt;', versions)
        self.assert_escaped(versions, self.TITLE)

    def test_log_search_page(self):
        # mongomock has no text search, so the query itself is stood in for.
        text = 'first line\n<i>teaser</i> "needle"\nlast line\n'
        log_id = client.post('/api/1/log/upload', data={'log': text}).get_json()['id']
        found = [models.Log.objects(id=log_id).first()]
        with mock.patch('mongoengine.queryset.QuerySet.search_text', return_value=found):
            page = client.post('/log/search', data={'query': 'needle'}).get_data(as_text=True)
        self.assertIn('&lt;i&gt;teaser&lt;/i&gt;', page)
        self.assertNotIn('<i>teaser</i>', page)

    def test_highlighted_log_keeps_its_markup(self):
        log_id = client.post('/api/1/log/upload', data={'log': 'line one\n<b>line two</b>\n'}).get_json()['id']
        page = client.get('/log/' + log_id).get_data(as_text=True)
        self.assertIn('<table class="highlighttable">', page)
        self.assertNotIn('<b>line two</b>', page)
        # The stylesheet comes from pygments, not from a user, and has to reach
        # the page unchanged. Same formatter options as app/controllers/log.py.
        css = pygments.formatters.get_formatter_by_name(
            'html', linenos='table', lineanchors=True, anchorlinenos=True).get_style_defs()
        self.assertIn(css, page)

    def test_mail_text_is_not_escaped(self):
        for template in ('mail/register.txt', 'mail/reset.txt'):
            with self.subTest(template=template), app.test_request_context():
                body = render_template(template, username='A&B <x>',
                                       link='https://example.invalid/confirm?a=1&b=2')
                self.assertIn('A&B <x>', body)
                self.assertIn('?a=1&b=2', body)

    def test_which_templates_are_escaped(self):
        select = app.jinja_env.autoescape
        for name in ('mod_list.html.j2', 'new.html', 'new.svg', 'new.j2', None):
            with self.subTest(name=name):
                self.assertTrue(select(name))
        for name in ('mail/register.txt', 'mail/reset.txt'):
            with self.subTest(name=name):
                self.assertFalse(select(name))


class RawLogIsPlainText(Base):
    def test_raw_log_headers_and_body(self):
        text = '<h1>not a heading</h1>\nGrüße – 日本語\n'
        log_id = client.post('/api/1/log/upload', data={'log': text}).get_json()['id']
        resp = client.get('/log/%s/raw' % log_id)
        self.assertEqual(resp.headers['Content-Type'], 'text/plain; charset=utf-8')
        self.assertEqual(resp.headers['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(resp.get_data().decode('utf-8'), text)


class TeamRoleValues(Base):
    """mod/team/update accepts a role only if it equals one of the four known values."""

    def setUp(self):
        super().setUp()
        self.owner = make_user('owner')
        self.manager = make_user('manager')
        self.outsider = make_user('outsider')
        create_mod(self.owner, 'teammod')
        resp = self.update(self.owner, [('owner', models.TEAM_OWNER), ('manager', models.TEAM_MANAGER)])
        self.assertEqual(resp.get_json(), {'result': True})

    def update(self, headers, members):
        return client.post('/api/1/mod/team/update', headers=headers, json={
            'mid': 'teammod', 'members': [{'user': user, 'role': role} for user, role in members]})

    def team(self):
        """The stored team as it is, one (user, role) pair per entry."""
        return [(mem.user.username, mem.role) for mem in models.Mod.objects(mid='teammod').first().team]

    START = [('owner', 0), ('manager', 10)]

    def reset_team(self):
        """Put the stored team back, so each value in a loop starts from the same state."""
        mod = models.Mod.objects(mid='teammod').first()
        mod.team = [models.TeamMember(user=models.User.objects(username=name).first(), role=role)
                    for name, role in self.START]
        mod.save()

    def test_fractional_role_is_refused(self):
        for value in (0.5, 10.5, -0.5, 9.99):
            with self.subTest(value=value):
                self.reset_team()
                resp = self.update(self.manager, [('owner', 0), ('manager', value)])
                self.assertEqual(self.team(), self.START)
                self.assertEqual(resp.status_code, 400)

    def test_unknown_or_non_number_role_is_refused(self):
        for value in (5, 15, -1, 40, True, None, [0], {'x': 0}):
            with self.subTest(value=value):
                self.reset_team()
                resp = self.update(self.owner, [('owner', 0), ('manager', value)])
                self.assertEqual(self.team(), self.START)
                self.assertEqual(resp.status_code, 400)

    def test_text_that_is_not_a_whole_number_is_still_refused(self):
        for value in ('0.5', 'owner', ''):
            with self.subTest(value=value):
                resp = self.update(self.owner, [('owner', 0), ('manager', value)])
                self.assertEqual(self.team(), self.START)
                self.assertEqual(resp.status_code, 400)

    def test_values_equal_to_a_known_role_are_stored_as_that_role(self):
        # 0.0, 10.0 and false compare equal to a known role, in the owner
        # checks as well, and are stored as the whole number.
        for value, stored in ((20.0, 20), (30.0, 30), (10.0, 10)):
            with self.subTest(value=value):
                resp = self.update(self.owner, [('owner', 0), ('manager', value)])
                self.assertEqual(resp.get_json(), {'result': True})
                self.assertEqual(self.team(), [('owner', 0), ('manager', stored)])
        self.update(self.owner, self.START)
        for value in (0.0, False):
            with self.subTest(value=value):
                resp = self.update(self.manager, [('owner', 0), ('manager', value)])
                self.assertEqual(resp.get_json(), {'result': False, 'reason': 'owners_changed'})
                self.assertEqual(self.team(), self.START)

    def test_manager_still_cannot_change_owners(self):
        resp = self.update(self.manager, [('owner', 0), ('manager', 0)])
        self.assertEqual(resp.get_json(), {'result': False, 'reason': 'owners_changed'})
        self.assertEqual(self.team(), self.START)

    def test_known_roles_still_work(self):
        resp = self.update(self.owner, [('owner', 0), ('manager', models.TEAM_TESTER)])
        self.assertEqual(resp.get_json(), {'result': True})
        self.assertEqual(self.team(), [('owner', 0), ('manager', 30)])
        # Clients may send the role as a string of digits.
        resp = self.update(self.owner, [('owner', '0'), ('manager', '20')])
        self.assertEqual(resp.get_json(), {'result': True})
        self.assertEqual(self.team(), [('owner', 0), ('manager', 20)])

    def test_non_member_is_still_refused(self):
        resp = self.update(self.outsider, [('owner', 0), ('outsider', 0)])
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(self.team(), self.START)

    def test_team_that_already_holds_an_unknown_role(self):
        # A known cost, not a goal: the whole list is refused until that
        # member is given a known role. Change this test with the behaviour.
        mod = models.Mod.objects(mid='teammod').first()
        mod.team.append(models.TeamMember(user=models.User.objects(username='outsider').first(), role=25))
        mod.save()
        resp = self.update(self.owner, [('owner', 0), ('manager', 10), ('outsider', 25)])
        self.assertEqual(resp.status_code, 400)
        resp = self.update(self.owner, [('owner', 0), ('manager', 10), ('outsider', 20)])
        self.assertEqual(resp.get_json(), {'result': True})
        self.assertEqual(self.team(), [('owner', 0), ('manager', 10), ('outsider', 20)])


if __name__ == '__main__':
    unittest.main(verbosity=2)
