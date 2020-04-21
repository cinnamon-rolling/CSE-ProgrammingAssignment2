from matplotlib import pyplot as plt


# time taken for CP1
# time_taken_ms = [419.817642, 53059.712434, 336301.383725,
#  638201.454264, 870219.157936, 941043.876785]

# time taken for CP2
time_taken_ms = [307.280745, 6374.206096,
                 31128.845705, 72165.697636, 103516.87502, 105373.578724]

data_size = [0, 10, 50, 100, 150, 200]
throughput_data_per_ms = [line/time for line,
                          time in zip(data_size, time_taken_ms)]
print(throughput_data_per_ms)

plt.plot(data_size, throughput_data_per_ms)
plt.xlabel("file size")
plt.ylabel("throughput (MB per ms)")
plt.show()
