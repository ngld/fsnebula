"""Tests for one fix: mod/team/update refuses a list that names a user twice,
and a user value that is not text.

    python tests/test_team_members.py

See tests/common.py for what is needed to run them.
"""
import unittest

from common import Base, client, create_mod, make_user, models


class RepeatedTeamMember(Base):
    START = [('owner', 0), ('manager', 10)]

    def setUp(self):
        super().setUp()
        self.owner = make_user('owner')
        self.manager = make_user('manager')
        create_mod(self.owner, 'teammod')
        self.assertEqual(self.update(self.owner, self.START).get_json(), {'result': True})

    def update(self, headers, members):
        return client.post('/api/1/mod/team/update', headers=headers, json={
            'mid': 'teammod', 'members': [{'user': user, 'role': role} for user, role in members]})

    def team(self):
        """The stored team as it is, one (user, role) pair per entry."""
        return [(mem.user.username, mem.role) for mem in models.Mod.objects(mid='teammod').first().team]

    def reset_team(self):
        """Put the stored team back, so each case in a loop starts from the same state."""
        mod = models.Mod.objects(mid='teammod').first()
        mod.team = [models.TeamMember(user=models.User.objects(username=name).first(), role=role)
                    for name, role in self.START]
        mod.save()

    def test_owner_listed_twice_by_a_manager(self):
        for members in ([('owner', 30), ('owner', 0), ('manager', 10)],
                        [('owner', 0), ('owner', 30), ('manager', 10)],
                        [('owner', 0), ('manager', 10), ('owner', 20)]):
            with self.subTest(members=members):
                self.reset_team()
                resp = self.update(self.manager, members)
                self.assertEqual(self.team(), self.START)
                self.assertEqual(resp.status_code, 400)
        # The owner can still manage the team.
        fetched = client.post('/api/1/mod/team/fetch', headers=self.owner, data={'mid': 'teammod'}).get_json()
        self.assertTrue(fetched['result'])

    def test_any_member_listed_twice(self):
        for members in ([('owner', 0), ('manager', 10), ('manager', 20)],
                        [('owner', 0), ('owner', 0), ('manager', 10)]):
            with self.subTest(members=members):
                self.reset_team()
                resp = self.update(self.owner, members)
                self.assertEqual(self.team(), self.START)
                self.assertEqual(resp.status_code, 400)

    def test_user_that_is_not_text(self):
        # The object stands for "a user who is neither of these two", which
        # here is one user not otherwise in the list, so only the text check
        # can refuse it.
        make_user('bystander')
        for value in ({'$nin': ['owner', 'manager']}, ['bystander'], 5, None, True):
            with self.subTest(value=value):
                self.reset_team()
                resp = self.update(self.owner, [('owner', 0), ('manager', 10), (value, 20)])
                self.assertEqual(self.team(), self.START)
                self.assertEqual(resp.status_code, 400)

    def test_ordinary_update_still_works(self):
        make_user('newcomer')
        resp = self.update(self.owner, [('owner', 0), ('manager', 10), ('newcomer', 30)])
        self.assertEqual(resp.get_json(), {'result': True})
        self.assertEqual(self.team(), [('owner', 0), ('manager', 10), ('newcomer', 30)])
        resp = self.update(self.owner, [('owner', 0), ('ghost', 10)])
        self.assertEqual(resp.get_json(), {'result': False, 'reason': 'member_not_found', 'member': 'ghost'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
