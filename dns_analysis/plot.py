import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import sys

data = pd.read_csv(sys.argv[1])
binsize = int(sys.argv[2])

sns.set(color_codes=True)
max_count = data.max().max()
n_bins = len(data)
(fig, ax) = plt.subplots(2, len(data.columns))
for a in ax[0]:
    a.set_ylim(top = max_count + binsize/10)

def plot(ns, color, axis):
    y = data[ns]
    total = np.sum(y)
    s = 0
    i1 = 0
    i2 = 0
    i2_done = False
    for d in y:
        s += d
        i1 += 1
        if s/total >= 0.50 and not i2_done:
            i2 = i1
            i2_done = True
        if s/total >= 0.90:
            break
    sns.barplot(x=y.index, y=y, ax=axis[0], color=color, edgecolor=color)
    axis[0].axvline(x=i2, color=color, linestyle='-', label="50th percentile")
    axis[0].axvline(x=i1, color=color, linestyle='--', label="90th percentile")
    axis[0].set_xticks(np.arange(n_bins, step=int(n_bins/10)))
    axis[0].set_xticklabels(np.arange(n_bins, step=int(n_bins/10)))
    axis[0].legend()
    y = np.log(y[:int(40*n_bins/100)])
    sns.regplot(x=y.index, y=y, ax=axis[1], color=color)

    axis[0].set_title(ns)
    axis[0].set_xlabel("bin ID, by domain popularity")
    axis[0].set_ylabel("# of cached domains in bin (bin size="+str(binsize)+")")
    axis[1].set_title(ns+", linear fitting of log transformation for bucket 0-"+str(int(4/10*n_bins)))
    axis[1].set_xlabel(axis[0].get_xlabel())
    axis[1].set_ylabel("log(#)")


colors = ["red", "green", "blue", "magenta"]
for (i, (ns, color)) in enumerate(zip(data.columns, colors)):
    plot(ns, color, ax[:, i])

fig.suptitle("DNS Cache Data Distribution (ordered by Cisco Umbrella Top 1M domains list)")
plt.show()
