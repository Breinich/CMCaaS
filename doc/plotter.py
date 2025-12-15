from matplotlib import pyplot as plt

def main():
    enclave_times = [41365, 40542, 35980, 40196, 40660, 36485]
    bare_times = [1169, 1109, 1022, 1006, 1019, 1170]

    # 6 test runs
    runs = list(range(1, 7))
    plt.plot(runs, enclave_times, marker='o', label='Enclave')
    plt.plot(runs, bare_times, marker='o', label='Bare')
    plt.xlabel("Test Run")
    plt.ylabel("Time (ms)")
    plt.title("Enclave vs Bare Runner")
    plt.legend()
    plt.show()




if __name__ == "__main__":
    main()