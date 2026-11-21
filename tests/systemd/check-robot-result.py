"""Require a named Robot case to pass in one boot's result."""
import sys
import xml.etree.ElementTree as ET


result, name = sys.argv[1:]
try:
    root = ET.parse(result).getroot()
except (OSError, ET.ParseError) as error:
    raise SystemExit(f'Cannot read Robot result {result}: {error}')

matches = [test for test in root.findall('.//test') if test.get('name') == name]
statuses = [test.find('status') for test in matches]
if len(statuses) != 1 or statuses[0] is None or statuses[0].get('status') != 'PASS':
    raise SystemExit(f'Expected one PASS for Robot test {name!r} in {result}')
