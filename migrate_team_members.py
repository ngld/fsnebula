#!/usr/bin/env python

from app.models import Mod, TeamMember, TEAM_OWNER

print('Starting...')

for mod in Mod.objects:
    if len(mod.team) == 0 and len(mod.members) > 0:
        print(mod.title)

        for mem in mod.members:
            mod.team.append(TeamMember(user=mem, role=TEAM_OWNER))

        mod.members = []
        mod.save()


print('Done')
