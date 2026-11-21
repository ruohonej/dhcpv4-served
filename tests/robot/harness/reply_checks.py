"""DHCP expectations shared by the namespace and comparison drivers."""


def expected_reply(link, *, message_type=2, address=None, client_id=b'probe',
                   xid=0x12345678, dst='255.255.255.255', mac='ff'*6, minimal=False):
    number = link.removeprefix('lan')
    expected = {'src': f'192.168.{number}.1', 'dst': dst, 'mac': mac,
                'yiaddr': address or f'192.168.{number}.100', 'xid': xid, 'type': message_type,
                'server': f'192.168.{number}.1', 'client_id': client_id.hex(),
                'router': [f'192.168.{number}.1', f'192.168.{number}.102'],
                'dns': [f'192.168.{number}.1'], 'domain': f'lan{number}.example',
                'ntp': f'192.168.{number}.1'}
    if minimal:
        expected.update(router=None, dns=None, domain='', ntp=None,
                        option_codes=[1, 51, 53, 54, 58, 59, 61])
    return expected


def only_reply(link, replies):
    if len(replies) != 1 or not isinstance(replies[0], dict):
        raise AssertionError(f'{link}: expected one decodable DHCP reply, got {replies!r}')
    return replies[0]


def check_fields(link, reply, expected):
    if reply != expected:
        differences = [f'{key}: expected {value!r}, got {reply.get(key)!r}'
                       for key, value in expected.items() if key not in reply or reply[key] != value]
        extra = reply.keys() - expected.keys()
        if extra:
            differences.append(f'unexpected fields: {sorted(extra)}')
        raise AssertionError(f'{link}: ' + '; '.join(differences))
