import json
from collections import OrderedDict
from pathlib import Path


def to_camelcase(s: str) -> str:
    return ''.join([i.capitalize() for i in s.split('_')])


def fill_info(a, path):
    NAMES = []
    for proto in a:
        alt_name = ''
        if '/' in proto:
            proto, alt_name = proto.split('/')
        NAMES.append((proto, alt_name))

    for i in NAMES:
        if i[1]:
            a[i[0]] = a[f'{i[0]}/{i[1]}']
            a.pop(f'{i[0]}/{i[1]}')

    with open('pcc_info.frmt') as f:
        info_format = f.read()

    for full_name, alt_name in NAMES:
        in_block = False
        n_t = ''
        while info_format:
            ind = info_format.find('//')
            if ind >= 0:
                block = info_format[:ind]
                if in_block:
                    n_block = block
                    if 'FULL_NAME' in n_block:
                        if 'ALT_NAME' in n_block:
                            if alt_name:
                                n_block = n_block.replace('ALT_NAME', alt_name).replace('FULL_NAME', full_name)
                            else:
                                n_block = ''
                        else:
                            if 'FULL_NAME_CAMELCASE' in n_block:
                                n_block = n_block.replace('FULL_NAME_CAMELCASE', to_camelcase(full_name))
                            n_block = n_block.replace('FULL_NAME', full_name)
                    else:
                        if 'ALT_NAME' in n_block:
                            if alt_name:
                                n_block = n_block.replace('ALT_NAME', alt_name)
                            else:
                                n_block = ''
                    n_t += n_block
                    n_t += f'//{block}//'
                    in_block = False
                else:
                    n_t += block
                    in_block = True
                info_format = info_format[ind + 2:]
            else:
                n_t += info_format
                break
        info_format = n_t

    in_block = False
    n_t = ''
    while info_format:
        ind = info_format.find('//')
        if ind >= 0:
            block = info_format[:ind]
            if in_block:
                in_block = False
            else:
                n_t += block
                in_block = True
            info_format = info_format[ind + 2:]
        else:
            n_t += info_format
            break
    info_format = n_t.replace(', }', '}').replace(', \n', '\n')
    with open(f'{path}/__init__.py', 'w') as f:
        f.write(info_format)


def generate_subclass(name, fields):
    with open('pcc_subclass.frmt') as f:
        format = f.read().replace('MOTHER_FIELD_CAMELCASE', to_camelcase(name))

    FIELDS_SIMPLE = []
    FIELDS_COMPLEX = OrderedDict()

    for field in fields:
        if fields[field]:
            FIELDS_COMPLEX[field] = OrderedDict()
            for subfield in fields[field]:
                FIELDS_COMPLEX[field][subfield] = fields[field][subfield]
        else:
            FIELDS_SIMPLE.append(field)

    ret = populate_simple(format, FIELDS_SIMPLE)
    ret = populate_complex(ret, FIELDS_COMPLEX)
    ret = ret.replace(', )', ')')
    ret = '\n'.join(['    ' + i if i else i for i in ret.split('\n')])
    return ret


def populate_simple(format: str, FIELDS_SIMPLE: list) -> str:
    for field in FIELDS_SIMPLE:  # populate FIELDS_SIMPLE format blocks
        in_block = False
        ret = ''
        while format:
            ind = format.find('//')
            if ind >= 0:
                block = format[:ind]
                if in_block:
                    if 'FIELDS_SIMPLE' in block:
                        ret += block.replace('FIELDS_SIMPLE', f'{field}')
                    ret += f'//{block}//'
                    in_block = False
                else:
                    ret += f'{block}'
                    in_block = True
                format = format[ind + 2:]
            else:
                ret += format
                break
        format = ret

    in_block = False
    ret = ''  # remove FIELDS_SIMPLE format blocks
    while format:
        ind = format.find('//')
        if ind >= 0:
            block = format[:ind]
            if in_block:
                if 'FIELDS_SIMPLE' not in block:
                    ret += f'//{block}//'
                in_block = False
            else:
                ret += f'{block}'
                in_block = True
            format = format[ind + 2:]
        else:
            ret += format
            break

    return ret


def get_subfields(fields):
    ret = []

    for subfield in fields:
        if fields[subfield]:
            for i in get_subfields(fields[subfield]):
                ret.append(f'{subfield}.{i}')
        else:
            ret.append(subfield)

    return ret


def populate_complex(format:str, FIELDS_COMPLEX: OrderedDict) -> str:
    for field_complex in FIELDS_COMPLEX:  # populate FIELDS_COMPLEX format blocks
        format += generate_subclass(field_complex, FIELDS_COMPLEX[field_complex])
        in_block = False
        ret = ''
        while format:
            ind = format.find('//')
            if ind >= 0:
                block = format[:ind]
                if in_block:
                    if 'FIELDS_COMPLEX' in block:
                        n_block = block
                        if 'FIELDS_COMPLEX.SUBFIELDS' in n_block:
                            n_n_block = ''
                            for i in get_subfields(FIELDS_COMPLEX[field_complex]):
                                n_n_block += n_block.replace('FIELDS_COMPLEX.SUBFIELDS',
                                                             f'{field_complex}.{i}')
                            n_block = n_n_block
                        if 'LEN_FIELDS_COMPLEX' in n_block:
                            tml = n_block[n_block.find('/{'):n_block.find('}/')+2]
                            n_block = n_block.replace(f'{tml}*LEN_FIELDS_COMPLEX', tml[2:-2]*len(FIELDS_COMPLEX[field_complex]))
                        if 'FIELDS_COMPLEX_CAMELCASE' in n_block:
                            n_block = n_block.replace('FIELDS_COMPLEX_CAMELCASE',
                                                      f'{to_camelcase(field_complex)}')
                        if 'FIELDS_COMPLEX' in n_block:
                            n_block = n_block.replace('FIELDS_COMPLEX', f'{field_complex}')
                        ret += n_block
                    ret += f'//{block}//'
                    in_block = False
                else:
                    ret += f'{block}'
                    in_block = True
                format = format[ind + 2:]
            else:
                ret += format
                break
        format = ret
    in_block = False
    ret = ''  # remove FIELDS_COMPLEX format blocks
    while format:
        ind = format.find('//')
        if ind >= 0:
            block = format[:ind]
            if in_block:
                if 'FIELDS_COMPLEX' not in block:
                    ret += f'//{block}//'
                in_block = False
            else:
                ret += f'{block}'
                in_block = True
            format = format[ind + 2:]
        else:
            ret += format
            break
    return ret


def fill_protos(a, path, replace=False):
    with open('pcc_main.frmt') as f:
        format = f.read()

    for proto in a:
        PROTOCOL = proto
        PROTOCOL_CAMELCASE = to_camelcase(proto)
        FIELDS_SIMPLE = []
        FIELDS_COMPLEX = OrderedDict()
        for field in a[proto]:
            if a[proto][field]:
                FIELDS_COMPLEX[field] = OrderedDict()
                for subfield in a[proto][field]:
                    FIELDS_COMPLEX[field][subfield] = a[proto][field][subfield]
            else:
                FIELDS_SIMPLE.append(field)

        if not (Path(f'{path}/{PROTOCOL}.py').is_file()) or replace:
            with open(f'{path}/{PROTOCOL}.py', 'w') as f:
                t = format.replace('PROTOCOL_CAMELCASE', PROTOCOL_CAMELCASE).replace('PROTOCOL', PROTOCOL)
                t = populate_simple(t, FIELDS_SIMPLE)
                t = populate_complex(t, FIELDS_COMPLEX)
                t = t.replace(', )', ')')
                f.write(t)


with open('pcc_in.json') as f:
    a = json.loads(f.read())
    path = Path().resolve().parent
    fill_info(a, path)
    fill_protos(a, path, replace=False)
