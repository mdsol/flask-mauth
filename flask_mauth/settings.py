# -*- coding: utf-8 -*-

import re


# DEFAULT FLAGS
x_mws_time = 'X_MWS_TIME'
x_mws_authentication = 'X_MWS_AUTHENTICATION'
mws_token = "MWS"

# Parser for Signature
signature_info = re.compile(r'\A([^ ]+) *([^:]+):([^:]+)\Z')

# regex for a UUID, to avoid issues with wags passing ../../ statements
uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)