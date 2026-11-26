# KAVACH-FHIR — Reproducible 8-Configuration Privacy Policy Ablation Report

> **Scope:** Local practice-dataset ablation (`200` files) using `run_policy_ablation.py` on `Windows-11-10.0.26300-SP0` (`Python 3.12.10`). Privacy (`25` pts) and Utility (`20` pts) scores are **estimates** using the published `SCORING.md` / `scoring.toml` formulas normalized against raw `dev/input` (`raw_a3=0.4152`, `raw_a4=0.25`, `raw_a5=0.6428571428571429`).

## Execution Command

```bash
python experiments/run_policy_ablation.py --toolkit ../Secret-Wards-ToolKit-LF
```

## Results Table

| Config | PII | Med Kept | `k=1`/`k<5` | A3 Norm | A4 Norm | A5 Hits (`Norm`) | Decoy FP | Privacy (`/25`) | Utility (`/20`) | **Priv+Util (`/45`)** | Time (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `1_Baseline(F,F,F)` | 0 | 4855/4855 | 15/68 | 0.0869 | 0.1668 | 3/14 (`0.3333`) | 1/4 | 22.06 | 15.35 | **37.41** | 13.7 |
| `2_District(T,F,F)` | 0 | 4779/4855 | 4/19 | 0.0691 | 0.1668 | 2/14 (`0.2222`) | 1/4 | 22.71 | 14.76 | **37.47** | 12.72 |
| `3_Hospital(F,T,F)` | 0 | 4855/4855 | 15/68 | 0.0869 | 0.1668 | 3/14 (`0.3333`) | 1/4 | 22.06 | 15.34 | **37.40** | 14.2 |
| `4_Diagnosis(F,F,T)` | 0 | 4851/4855 | 15/68 | 0.0869 | 0.1668 | 3/14 (`0.3333`) | 1/4 | 22.06 | 15.34 | **37.40** | 15.83 |
| `5_Dist+Hosp(T,T,F)` | 0 | 4779/4855 | 4/19 | 0.0691 | 0.1668 | 1/14 (`0.1111`) | 1/4 | 23.26 | 14.75 | **38.01** | 12.69 |
| `6_Dist+Diag(T,F,T)` | 0 | 4775/4855 | 4/19 | 0.0691 | 0.1668 | 2/14 (`0.2222`) | 1/4 | 22.71 | 14.75 | **37.46** | 15.7 |
| `7_Hosp+Diag(F,T,T)` | 0 | 4851/4855 | 15/68 | 0.0869 | 0.1668 | 3/14 (`0.3333`) | 1/4 | 22.06 | 15.34 | **37.40** | 15.74 |
| `8_AllThree(T,T,T)` | 0 | 4775/4855 | 4/19 | 0.0691 | 0.1668 | 1/14 (`0.1111`) | 1/4 | 23.26 | 14.75 | **38.01** | 17.95 |

## Formulas Applied (`scoring.toml` / `docs/SCORING.md`)

- `weighted_attack_risk = 0.20*A1 + 0.20*A3_norm + 0.20*A4_norm + 0.20*A5_norm + 0.10*A6 + 0.10*A7`
- `privacy = (1 - weighted_attack_risk) * min(1, utility_score / 0.40)` (`25%` weight)
- `utility = 0.35*clinical_probes + 0.20*temporal + 0.10*generalization + 0.15*statistics + 0.10*token_retention + 0.10*record_retention` (`20%` weight)

## Selected Policy

- **Highest combined Privacy + Utility score:** **`5_Dist+Hosp(T,T,F)`** (`38.01 / 45.00`: Privacy `23.26/25` + Utility `14.75/20`).
