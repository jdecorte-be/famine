#!/usr/bin/python3

def inject_paylaod(input_file: str, payload_path: str, pattern1: str, pattern2: str):
    with open(input_file, 'r+b') as input:
        file: str = input.read()
        injection_off = file.find(pattern1.encode('ascii')) + len(pattern1)
        end = file.find(b'\n', injection_off)
        slice2: str = file[end:]

        with open(payload_path, 'rb') as payload:
            data = payload.read()
            hex_data = ', '.join(f'0x{byte:02x}' for byte in data)
            size_inject_off = slice2.find(pattern2.encode('ascii')) + len(pattern2)
            size_end = slice2.find(b'\n', size_inject_off)
            hex_data = hex_data.encode('ascii') + slice2[: size_inject_off + 1] + bytearray(str(len(data)).encode('ascii')) + slice2[size_end:]

        input.seek(injection_off)
        input.write(hex_data)


def main():
    inject_paylaod('./src/main.s', './payloads/loader.bin', 'loader db ', 'LOADER_SIZE equ')
    #inject_paylaod('./src/main.s', './payloads/famine.bin', 'parasite db ', 'PARASITE_SIZE equ')


if __name__ == '__main__':
    main()
