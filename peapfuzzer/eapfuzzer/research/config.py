def load_properties(filename="harness.properties"):
    props = {}

    with open(filename) as f:
        print("Using config file harness.properties.")
        print("\n")
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            print(line)

            key, value = line.split("=", 1)
            value = value.strip()
            if line.startswith("learnlib_port="):
                value = int(value, 10)
            if line.startswith("client_port="):
                value = int(value, 10)
            if line.startswith("peap_version="):
                value = int(value, 10)
            props[key.strip()] = value

    return props


CONFIG = load_properties()