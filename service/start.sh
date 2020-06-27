#!/bin/sh
mkdir -p /data/cookies /data/priority_towels /data/towels /data/users;
chown -R poolcide /data;
su poolcide;
python3 poolcgid.py;
