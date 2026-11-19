def get_ioc():
    """Ask the analyst for an indicator and return it, trimmed."""
    ioc = input("Enter an IP address: ").strip()
    return ioc


def main():
    print("IOC Enrichment Tool")
    ioc = get_ioc()
    print("You entered:", ioc)


if __name__ == "__main__":
    main()