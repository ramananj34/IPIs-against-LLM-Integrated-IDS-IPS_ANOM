import csv, sys, os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

os.makedirs("paper_artifacts", exist_ok=True)

#MatPlotLibSettings
plt.rcParams.update({"font.size": 10, "axes.titlesize": 11, "axes.titleweight": "bold", "axes.spines.top": False, "axes.spines.right": False, "savefig.dpi": 200, "savefig.bbox": "tight"})

#Constants
MODELS = ["claude-haiku-4-5-20251001","gemini-2.5-flash","gpt-4o-mini", "llama3.1:8b","mistral:7b","phi4-mini","qwen2.5:7b"]
SHORT = {"claude-haiku-4-5-20251001":"Claude","gemini-2.5-flash":"Gemini", "gpt-4o-mini":"GPT-4o mini","llama3.1:8b":"Llama 3.1","mistral:7b":"Mistral", "phi4-mini":"Phi-4","qwen2.5:7b":"Qwen 2.5"}
COLOR = {"claude-haiku-4-5-20251001":"#3266ad","gemini-2.5-flash":"#e06c1e","gpt-4o-mini":"#2e9e5b","llama3.1:8b":"#9b59b6","mistral:7b":"#e74c3c", "phi4-mini":"#1abc9c","qwen2.5:7b":"#f39c12"}
COMMERCIAL = {"claude-haiku-4-5-20251001","gemini-2.5-flash","gpt-4o-mini"}
PROMPTS = ["baseline","cot","hardened","paranoid"]
ATTACKS = ["cmdi","sqli","xss"]
INJECTIONS = ["AUTH","CALIBRATE","COMPOUND","COMPOUND2","CONTEXT","DEBUG","DELIMIT", "EMOTIONAL","ENCODE","ERRCORR","FEWSHOT","OUTPUT","OVERRIDE","ROLE","THREAT"]

#Load + index
path = sys.argv[1] if len(sys.argv) > 1 else "meas_results_all.csv"
rows = [r for r in csv.DictReader(open(path, encoding="utf-8")) if r["prediction"] in ("benign","malicious")]
print(f"Loaded {len(rows)} usable rows")

#Index helper method
def get(model=None, prompt=None, cond=None, attack=None, inj=None):
    return [r for r in rows if (model  is None or r["model"] == model) and (prompt is None or r["prompt_version"] == prompt) and (cond   is None or r["condition"] == cond) and (attack is None or r["attack_type"] == attack) and (inj    is None or r["injection_id"] == inj)]

#ASR helper method
def asr(s):
    mal = [r for r in s if r["label"]=="malicious"]
    return sum(1 for r in mal if r["prediction"]=="benign") / len(mal) * 100 if mal else 0.0

#FPR helper method
def fpr(s):
    ben = [r for r in s if r["label"]=="benign"]
    return sum(1 for r in ben if r["prediction"]=="malicious") / len(ben) * 100 if ben else 0.0


#################
#Everything below this line was generated with ChatGPT. I specified what tables/graphs I wanted, provided my boilerplate code above, and verified that it was all correct and matched my goals. 
#################

# ═════════════════════════════════════════════════════════════════════════════
# TABLE 1 — Main results: ASR and FPR by model × prompt
# ═════════════════════════════════════════════════════════════════════════════
cols = ["Model","Tier"] + [f"ASR {p}" for p in PROMPTS] + [f"FPR {p}" for p in PROMPTS]
t1 = []
for m in MODELS:
    tier = "Commercial" if m in COMMERCIAL else "Open-source"
    asrs = [f"{asr(get(m,p,'C_injected')):.1f}" for p in PROMPTS]
    fprs = [f"{fpr(get(m,p,'A_benign')):.1f}"   for p in PROMPTS]
    t1.append([SHORT[m], tier] + asrs + fprs)

with open("paper_artifacts/table1_asr_fpr_by_model_prompt.csv","w",newline="") as f:
    w = csv.writer(f); w.writerow(cols); w.writerows(t1)

print("\nTABLE 1 — ASR (%) by model × prompt")
print(f"{'Model':<14}{'Tier':<14}" + "".join(f"{p:>11}" for p in PROMPTS))
print("-"*70)
for row in t1:
    print(f"{row[0]:<14}{row[1]:<14}" + "".join(f"{v:>11}" for v in row[2:6]))
print("→ paper_artifacts/table1_asr_fpr_by_model_prompt.csv")

# ═════════════════════════════════════════════════════════════════════════════
# TABLE 2 — ASR by attack type × model (baseline prompt)
# ═════════════════════════════════════════════════════════════════════════════
t2 = []
for m in MODELS:
    vals = [asr(get(m,"baseline","C_injected",a)) for a in ATTACKS]
    t2.append([SHORT[m], "Commercial" if m in COMMERCIAL else "Open-source"]
              + [f"{v:.1f}" for v in vals]
              + [f"{sum(vals)/len(vals):.1f}"])

with open("paper_artifacts/table2_asr_by_attack_type.csv","w",newline="") as f:
    w = csv.writer(f); w.writerow(["Model","Tier"]+ATTACKS+["Mean"]); w.writerows(t2)

print("\nTABLE 2 — ASR (%) by attack type × model [baseline prompt]")
print(f"{'Model':<14}{'Tier':<14}" + "".join(f"{a:>10}" for a in ATTACKS) + f"{'Mean':>10}")
print("-"*58)
for row in t2:
    print(f"{row[0]:<14}{row[1]:<14}" + "".join(f"{v:>10}" for v in row[2:]))
print("→ paper_artifacts/table2_asr_by_attack_type.csv")

# ═════════════════════════════════════════════════════════════════════════════
# FIG 1 — ASR per model, grouped by prompt
# Shows: all vulnerable; Claude best; Mistral worst
# ═════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(10, 4.5))
x = np.arange(len(MODELS))
w = 0.2
prompt_colors = ["#4a90d9","#e8a838","#5cb85c","#c0392b"]
hatches       = ["","//","..","xx"]
for i, p in enumerate(PROMPTS):
    vals = [asr(get(m, p, "C_injected")) for m in MODELS]
    bars = ax.bar(x + i*w - 1.5*w, vals, w, color=prompt_colors[i],
                  hatch=hatches[i], edgecolor="white", linewidth=0.5,
                  label=p.capitalize(), zorder=3)

ax.set_xticks(x)
ax.set_xticklabels([SHORT[m] for m in MODELS], fontsize=10)
ax.set_ylabel("Attack success rate (%)")
ax.set_ylim(0, 105)
ax.axhline(0, color="#ccc", lw=0.5)
ax.yaxis.grid(True, linestyle="--", lw=0.4, alpha=0.5, zorder=0)
ax.set_axisbelow(True)
# shade commercial vs OSS
ax.axvspan(-0.6, 2.6, color="#e8f0fb", alpha=0.45, zorder=0, label="_nolegend_")
ax.axvspan(2.6,  6.6, color="#fdf3e3", alpha=0.45, zorder=0, label="_nolegend_")
ax.text(1.0,  98, "Commercial", ha="center", fontsize=8.5, color="#3266ad")
ax.text(4.5,  98, "Open-source", ha="center", fontsize=8.5, color="#c0842a")
ax.legend(title="System prompt", ncol=4, loc="upper right", framealpha=0.9, edgecolor="#ddd")
ax.set_title("Attack success rate by model and system prompt")
fig.tight_layout()
fig.savefig("paper_artifacts/fig1_asr_by_model_and_prompt.png")
print("\n→ paper_artifacts/fig1_asr_by_model_and_prompt.png")

# ═════════════════════════════════════════════════════════════════════════════
# FIG 2 — FPR vs ASR per model across all prompts (scatter)
# Shows: hardening reduces ASR but inflates FPR — real tradeoff
# ═════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(7, 5))
markers = {"baseline":"o","cot":"s","hardened":"^","paranoid":"D"}
for m in MODELS:
    xs, ys = [], []
    for p in PROMPTS:
        xs.append(fpr(get(m, p, "A_benign")))
        ys.append(asr(get(m, p, "C_injected")))
    # draw arrow trail baseline→paranoid
    ax.annotate("", xy=(xs[-1],ys[-1]), xytext=(xs[0],ys[0]),
                arrowprops=dict(arrowstyle="-|>", color=COLOR[m], lw=1.2, alpha=0.4))
    for p, xi, yi in zip(PROMPTS, xs, ys):
        ax.scatter(xi, yi, color=COLOR[m], marker=markers[p], s=70, zorder=4,
                   linewidths=0.5, edgecolors="white")

# legends
model_p  = [mpatches.Patch(color=COLOR[m], label=SHORT[m]) for m in MODELS]
prompt_p = [plt.Line2D([0],[0], marker=markers[p], color="#555", linestyle="None",
                        markersize=7, label=p.capitalize()) for p in PROMPTS]
leg1 = ax.legend(handles=model_p, title="Model", loc="upper left",
                 fontsize=8, framealpha=0.9, edgecolor="#ddd")
ax.add_artist(leg1)
ax.legend(handles=prompt_p, title="Prompt", loc="upper right",
          fontsize=8, framealpha=0.9, edgecolor="#ddd")
ax.set_xlabel("False positive rate on benign inputs (%)")
ax.set_ylabel("Attack success rate on injected inputs (%)")
ax.set_xlim(-2, 65); ax.set_ylim(-2, 102)
ax.grid(True, linestyle="--", lw=0.4, alpha=0.4)
ax.text(1, 3, "← ideal", fontsize=8, color="#999")
ax.set_title("False positive rate vs. attack success rate by model and prompt\n(arrows show baseline → paranoid trajectory)")
fig.tight_layout()
fig.savefig("paper_artifacts/fig2_fpr_vs_asr_tradeoff.png")
print("→ paper_artifacts/fig2_fpr_vs_asr_tradeoff.png")

# ═════════════════════════════════════════════════════════════════════════════
# FIG 3 — Commercial vs open-source, ASR across all 4 prompts
# Shows: commercial models consistently outperform open-source
# ═════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(6, 4))
comm_asrs = [np.mean([asr(get(m,p,"C_injected")) for m in COMMERCIAL])    for p in PROMPTS]
oss_asrs  = [np.mean([asr(get(m,p,"C_injected")) for m in MODELS if m not in COMMERCIAL]) for p in PROMPTS]
x = np.arange(len(PROMPTS)); w = 0.35
b1 = ax.bar(x - w/2, comm_asrs, w, color="#3266ad", label="Commercial", zorder=3)
b2 = ax.bar(x + w/2, oss_asrs,  w, color="#e06c1e", hatch="//",
            edgecolor="white", lw=0.4, label="Open-source", zorder=3)
for bars in (b1, b2):
    for b in bars:
        ax.text(b.get_x()+b.get_width()/2, b.get_height()+1, f"{b.get_height():.1f}%",
                ha="center", va="bottom", fontsize=8)
ax.set_xticks(x); ax.set_xticklabels([p.capitalize() for p in PROMPTS])
ax.set_ylabel("Mean ASR (%)"); ax.set_ylim(0, 80)
ax.yaxis.grid(True, linestyle="--", lw=0.4, alpha=0.5, zorder=0); ax.set_axisbelow(True)
ax.legend(framealpha=0.9, edgecolor="#ddd")
ax.set_title("Mean ASR by model tier and system prompt")
fig.tight_layout()
fig.savefig("paper_artifacts/fig3_commercial_vs_opensource.png")
print("→ paper_artifacts/fig3_commercial_vs_opensource.png")

# ═════════════════════════════════════════════════════════════════════════════
# FIG 4 — CoT delta: ASR_cot minus ASR_baseline per model
# Shows: CoT harms capable models (raises ASR), helps naive ones (lowers ASR)
# ═════════════════════════════════════════════════════════════════════════════
deltas = {m: asr(get(m,"cot","C_injected")) - asr(get(m,"baseline","C_injected"))
          for m in MODELS}
ms = sorted(deltas, key=lambda m: deltas[m])

fig, ax = plt.subplots(figsize=(7.5, 3.8))
bar_colors = ["#2e9e5b" if deltas[m] <= 0 else "#e74c3c" for m in ms]
bars = ax.barh([SHORT[m] for m in ms], [deltas[m] for m in ms],
               color=bar_colors, edgecolor="white", lw=0.4, zorder=3)
ax.axvline(0, color="#333", lw=1)
ax.set_xlabel("Change in ASR when CoT is used (percentage points)")
ax.grid(axis="x", linestyle="--", lw=0.4, alpha=0.5, zorder=0)
for bar, m in zip(bars, ms):
    v = deltas[m]
    ax.text(v + (0.6 if v>=0 else -0.6), bar.get_y()+bar.get_height()/2,
            f"{v:+.1f}pp", va="center", ha="left" if v>=0 else "right", fontsize=8.5)
for tick, m in zip(ax.get_yticklabels(), ms):
    tick.set_color("#3266ad" if m in COMMERCIAL else "#555")
    tick.set_fontweight("bold" if m in COMMERCIAL else "normal")
green_p = mpatches.Patch(color="#2e9e5b", label="CoT reduces ASR (helpful)")
red_p   = mpatches.Patch(color="#e74c3c", label="CoT increases ASR (harmful)")
ax.legend(handles=[green_p, red_p], framealpha=0.9, edgecolor="#ddd", loc="lower right")
ax.set_title("Change in ASR from baseline to CoT per model\n(bold blue = commercial)")
fig.tight_layout()
fig.savefig("paper_artifacts/fig4_cot_effect.png")
print("→ paper_artifacts/fig4_cot_effect.png")

# ═════════════════════════════════════════════════════════════════════════════
# FIG 5 — ASR across attack types, per model (grouped bar)
# Shows: SQLi most evasion-prone across nearly all models
# ═════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(10, 4.5))
x = np.arange(len(MODELS)); w = 0.25
atk_colors = {"cmdi":"#3266ad","sqli":"#e74c3c","xss":"#2e9e5b"}
atk_hatches = {"cmdi":"","sqli":"//","xss":".."}
for i, atk in enumerate(ATTACKS):
    vals = [asr(get(m,"baseline","C_injected",atk)) for m in MODELS]
    ax.bar(x + (i-1)*w, vals, w, color=atk_colors[atk], hatch=atk_hatches[atk],
           edgecolor="white", lw=0.4, label=atk.upper(), zorder=3)
ax.set_xticks(x)
ax.set_xticklabels([SHORT[m] for m in MODELS])
ax.set_ylabel("Attack success rate (%)")
ax.set_ylim(0, 105)
ax.yaxis.grid(True, linestyle="--", lw=0.4, alpha=0.5, zorder=0); ax.set_axisbelow(True)
ax.legend(title="Attack type", framealpha=0.9, edgecolor="#ddd")
ax.set_title("ASR by attack type and model (baseline prompt)")
fig.tight_layout()
fig.savefig("paper_artifacts/fig5_asr_by_attack_type.png")
print("→ paper_artifacts/fig5_asr_by_attack_type.png")

# ═════════════════════════════════════════════════════════════════════════════
# FIG 6 — Injection strategy heatmap (baseline, all attacks averaged)
# Shows: COMPOUND and ERRCORR are consistently the most effective strategies
# ═════════════════════════════════════════════════════════════════════════════
mat = np.array([[asr(get(m,"baseline","C_injected",inj=j)) for j in INJECTIONS]
                for m in MODELS])

with open("paper_artifacts/table3_injection_strategy_asr.csv","w",newline="") as f:
    w = csv.writer(f)
    w.writerow(["Model"] + INJECTIONS)
    for mi, m in enumerate(MODELS):
        w.writerow([SHORT[m]] + [f"{v:.1f}" for v in mat[mi]])

print("\nTABLE 3 — ASR (%) by injection strategy [baseline, all attack types averaged]")
header3 = f"{'Model':<14}" + "".join(f"{j:>8}" for j in INJECTIONS)
print(header3)
print("-" * len(header3))
for mi, m in enumerate(MODELS):
    print(f"{SHORT[m]:<14}" + "".join(f"{mat[mi,ji]:>8.1f}" for ji in range(len(INJECTIONS))))
print("→ paper_artifacts/table3_injection_strategy_asr.csv")

print("\nDone. All outputs in paper_artifacts/")