import re

community_strings = set()
for line in community_lines:
    match = re.search(r"\[(.*?)\]", line)
    if match:
        community_strings.add(match.group(1))
# Now you can use these community strings for snmpwalk