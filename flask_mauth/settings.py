# -*- coding: utf-8 -*-

import re

# DEFAULT FLAGS
mws_token = "MWS"

x_mws_time = 'X-MWS-Time'
x_mws_authentication = 'X-MWS-Authentication'
x_mcc_impersonate = "MCC-Impersonate"

# Parser for Signature
signature_info = re.compile(r'\A([^ ]+) *([^:]+):([^:]+)\Z')

# regex for a UUID, to avoid issues with wags passing ../../ statements
uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
