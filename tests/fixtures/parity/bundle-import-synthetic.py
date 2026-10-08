# Synthetic bot config modelled on the shapes the Phase 24.1 acceptance needs.
# Every value is invented; none is a credential.
import os
token = 'EXAMPLE_DISCORD_TOKEN_NOT_REAL'
defprefix = '>'
colour = 0x800000
application_id = '708766134927442001'
owner_id = 123456789012345678
api_key = 'EXAMPLE_YT_KEY_ONE'
title = "Example Bot"
description = 'Plays {nothing}'
stats_url = f'https://example.invalid/stats?key={api_key}&id={application_id}'
api_key = 'EXAMPLE_YT_KEY_TWO'
channel_stats = f'https://example.invalid/channels?key={api_key}'
invite = f'https://discord.com/api/oauth2/authorize?client_id={application_id}&scope=bot&scope=applications.commands'
blink = f'https://example.invalid/blink?scope=bot&scope=bot&p={defprefix}'
click = '[Click me!](https://discord.com/api/oauth2/authorize?client_id=708766134927442001)'
volume = 0.5
debug = True
nothing = None
weird = f'{api_key!r}'
other = len(token)
