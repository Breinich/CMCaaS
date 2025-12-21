from matplotlib import pyplot as plt
import argparse

def main(save_path: str = None):
    test_samples = [
        (10, 171800, 23427),
        (0, 36441, 2366),
        (1, 38393, 2164),
        (2, 39114, 1791),
        (3, 37211, 1215),
        (4, 38519, 1279),
        (5, 39417, 1584),
        (8, 9122524, 2632971),
        (9, 37201, 1598),
        (11, 41689, 4156)
    ]

    test_samples.sort(key=lambda x: x[2])

    for sample in test_samples:
        print(f"Sample {sample[0]}: {sample[1]} ms (Enclave), {sample[2]} ms (Bare)")

    enclave_times = [sample[1] for sample in test_samples]
    bare_times = [sample[2] for sample in test_samples]
    labels = [f"S{sample[0]}" for sample in test_samples]
    x = list(range(len(test_samples)))

    # Combined figure: two stacked subplots with shared x-axis
    fig, (ax_top, ax_bot) = plt.subplots(
        2, 1, figsize=(12, 8), sharex=True, gridspec_kw={'height_ratios': [3, 1]}
    )

    # Top: Enclave vs Bare times (log scale)
    ax_top.set_yscale('log')
    ax_top.plot(x, enclave_times, marker='o', label='Enclave Time (ms)', color='#1f77b4')
    ax_top.plot(x, bare_times, marker='o', label='Bare Time (ms)', color='#ff7f0e')

    # Annotate a few extreme points to avoid clutter (top 3 by time)
    combined_max_indices = sorted(range(len(enclave_times)), key=lambda i: enclave_times[i], reverse=True)[:3]
    for i in combined_max_indices:
        ax_top.annotate(f"{enclave_times[i]:,} ms", (x[i], enclave_times[i]),
                        textcoords="offset points", xytext=(0, 8), ha='center', fontsize=8, color='#1f77b4')
    # annotate bare for the highest bare as well
    bare_max_idx = max(range(len(bare_times)), key=lambda i: bare_times[i])
    ax_top.annotate(f"{bare_times[bare_max_idx]:,} ms", (x[bare_max_idx], bare_times[bare_max_idx]),
                    textcoords="offset points", xytext=(0, -12), ha='center', fontsize=8, color='#ff7f0e')

    ax_top.set_ylabel('Time (ms, log scale)')
    ax_top.set_title('Enclave vs Bare Execution Times and Ratio')
    ax_top.grid(True, which='both', alpha=0.3)
    ax_top.legend()

    # Bottom: Ratio (Enclave / Bare)
    ratios = [enclave / bare if bare != 0 else float('nan') for enclave, bare in zip(enclave_times, bare_times)]
    ax_bot.bar(x, ratios, color='purple', alpha=0.6)
    ax_bot.plot(x, ratios, marker='o', linestyle='-', color='purple')

    # Horizontal baseline at ratio == 1
    ax_bot.axhline(1.0, color='gray', linestyle='--', linewidth=1)
    ax_bot.set_ylabel('Enclave / Bare')
    ax_bot.set_xlabel('Test Samples')
    ax_bot.set_xticks(x)
    ax_bot.set_xticklabels(labels, rotation=45, ha='right')

    # Annotate top ratios (largest 3)
    top_ratio_indices = sorted(range(len(ratios)), key=lambda i: ratios[i] if ratios[i] == ratios[i] else -1, reverse=True)[:3]
    for i in top_ratio_indices:
        ax_bot.annotate(f"{ratios[i]:.2f}", (x[i], ratios[i]),
                        textcoords="offset points", xytext=(0, 6), ha='center', fontsize=8, color='purple')

    ax_bot.grid(True, axis='y', alpha=0.3)

    plt.tight_layout()

    if save_path:
        fig.savefig(save_path, dpi=150, bbox_inches='tight')
        print(f"Saved combined plot to: {save_path}")

    plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot Enclave vs Bare times and their ratio (combined).")
    parser.add_argument("--save", "-s", help="Optional output path to save the combined plot (e.g. ./combined.png)")
    args = parser.parse_args()
    main(save_path=args.save)
