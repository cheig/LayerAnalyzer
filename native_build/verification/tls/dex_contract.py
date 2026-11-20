"""Read defined DEX methods for JNI audits (string presence alone is insufficient)."""
import struct


def uleb(data, offset):
    value = 0
    for shift in range(0, 35, 7):
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError("invalid DEX uleb128")


def read_dex(data):
    if data[:4] != b"dex\n" or len(data) < 112:
        raise ValueError("expected standard DEX")

    def table(offset, width):
        count, start = struct.unpack_from("<II", data, offset)
        if start + count * width > len(data):
            raise ValueError("DEX table out of bounds")
        return range(start, start + count * width, width)

    strings = []
    for pos in table(56, 4):
        start = struct.unpack_from("<I", data, pos)[0]
        _, start = uleb(data, start)
        end = data.index(0, start)
        # All names/descriptors used by this audit are ASCII. Other DEX strings
        # are MUTF-8 and are irrelevant to the JNI contract.
        strings.append(data[start:end].decode("utf-8", errors="replace"))
    types = [strings[struct.unpack_from("<I", data, p)[0]] for p in table(64, 4)]

    def type_list(offset):
        if not offset:
            return []
        count = struct.unpack_from("<I", data, offset)[0]
        return [types[struct.unpack_from("<H", data, offset + 4 + i * 2)[0]] for i in range(count)]

    protos = []
    for pos in table(72, 12):
        _, result, params = struct.unpack_from("<III", data, pos)
        protos.append("(" + "".join(type_list(params)) + ")" + types[result])
    methods = []
    for pos in table(88, 8):
        owner, proto, name = struct.unpack_from("<HHI", data, pos)
        methods.append((types[owner], strings[name], protos[proto]))
    classes = {}
    for pos in table(96, 32):
        cls, flags, parent, interfaces, _, _, class_data, _ = struct.unpack_from("<8I", data, pos)
        defined = {}
        if class_data:
            counts = []
            cursor = class_data
            for _ in range(4):
                count, cursor = uleb(data, cursor)
                counts.append(count)
            for _ in range(counts[0] + counts[1]):
                _, cursor = uleb(data, cursor)
                _, cursor = uleb(data, cursor)
            for count in counts[2:]:
                index = 0
                for _ in range(count):
                    delta, cursor = uleb(data, cursor)
                    access, cursor = uleb(data, cursor)
                    code, cursor = uleb(data, cursor)
                    index += delta
                    owner, name, descriptor = methods[index]
                    if owner != types[cls]:
                        raise ValueError("DEX method owner mismatch")
                    defined[(name, descriptor)] = {"access": access, "code": code}
        classes[types[cls]] = {"access": flags, "super": None if parent == 0xffffffff else types[parent],
                               "interfaces": type_list(interfaces), "methods": defined}
    return classes


def has_parent(classes, name, target, seen=None):
    if name == target:
        return True
    seen = set() if seen is None else seen
    if name in seen or name not in classes:
        return False
    seen.add(name)
    cls = classes[name]
    return any(has_parent(classes, parent, target, seen) for parent in [cls["super"], *cls["interfaces"]])


def resolve_method(classes, name, method):
    while name in classes:
        cls = classes[name]
        if method in cls["methods"]:
            return cls["methods"][method]
        name = cls["super"]
    return None
