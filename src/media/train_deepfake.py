# src/media/train_deepfake.py
from __future__ import annotations

import argparse
import csv
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Optional

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from PIL import Image

import torchvision.transforms as T
import torchvision.models as models


@dataclass
class Row:
    path: str
    label: int  # 0 real, 1 fake
    source: str
    origin: str


def _seed(seed: int) -> None:
    random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def _read_manifest(csv_path: Path) -> List[Row]:
    if not csv_path.exists():
        raise FileNotFoundError(f"manifest_not_found: {csv_path}")
    rows: List[Row] = []
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for x in r:
            rows.append(
                Row(
                    path=x["path"],
                    label=int(x["label"]),
                    source=x.get("source", ""),
                    origin=x.get("origin", ""),
                )
            )
    return rows


class FaceDataset(Dataset):
    def __init__(self, rows: List[Row], augment: bool, img_size: int):
        self.rows = rows
        if augment:
            self.tf = T.Compose(
                [
                    T.Resize((img_size, img_size)),
                    T.RandomHorizontalFlip(p=0.5),
                    T.ColorJitter(brightness=0.1, contrast=0.1, saturation=0.05, hue=0.02),
                    T.ToTensor(),
                    T.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
                ]
            )
        else:
            self.tf = T.Compose(
                [
                    T.Resize((img_size, img_size)),
                    T.ToTensor(),
                    T.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
                ]
            )

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, idx: int):
        row = self.rows[idx]
        # tolerate occasional broken files
        img = Image.open(row.path).convert("RGB")
        x = self.tf(img)
        y = torch.tensor(row.label, dtype=torch.long)
        return x, y


def build_model(arch: str) -> nn.Module:
    arch = (arch or "").strip().lower()

    # EfficientNet family
    # We keep ImageNet weights as strong baseline.
    if arch == "efficientnet_b0":
        m = models.efficientnet_b0(weights=models.EfficientNet_B0_Weights.IMAGENET1K_V1)
    elif arch == "efficientnet_b1":
        m = models.efficientnet_b1(weights=models.EfficientNet_B1_Weights.IMAGENET1K_V1)
    elif arch == "efficientnet_b2":
        m = models.efficientnet_b2(weights=models.EfficientNet_B2_Weights.IMAGENET1K_V1)
    elif arch == "efficientnet_b3":
        m = models.efficientnet_b3(weights=models.EfficientNet_B3_Weights.IMAGENET1K_V1)
    elif arch == "efficientnet_b4":
        m = models.efficientnet_b4(weights=models.EfficientNet_B4_Weights.IMAGENET1K_V1)
    elif arch == "efficientnet_b5":
        m = models.efficientnet_b5(weights=models.EfficientNet_B5_Weights.IMAGENET1K_V1)
    elif arch == "efficientnet_b6":
        m = models.efficientnet_b6(weights=models.EfficientNet_B6_Weights.IMAGENET1K_V1)
    elif arch == "efficientnet_b7":
        m = models.efficientnet_b7(weights=models.EfficientNet_B7_Weights.IMAGENET1K_V1)
    else:
        raise ValueError(
            f"unsupported_arch: {arch}. Use one of: efficientnet_b0..efficientnet_b7"
        )

    in_features = m.classifier[1].in_features
    m.classifier[1] = nn.Linear(in_features, 2)
    return m


@torch.no_grad()
def eval_epoch(model: nn.Module, loader: DataLoader, device: torch.device) -> Dict[str, float]:
    model.eval()
    total = 0
    correct = 0

    tp = fp = tn = fn = 0
    loss_sum = 0.0
    crit = nn.CrossEntropyLoss()

    for xb, yb in loader:
        xb = xb.to(device)
        yb = yb.to(device)
        logits = model(xb)
        loss = crit(logits, yb)
        loss_sum += float(loss.item()) * yb.size(0)

        pred = torch.argmax(logits, dim=1)
        total += yb.size(0)
        correct += int((pred == yb).sum().item())

        # label: 1=fake
        tp += int(((pred == 1) & (yb == 1)).sum().item())
        tn += int(((pred == 0) & (yb == 0)).sum().item())
        fp += int(((pred == 1) & (yb == 0)).sum().item())
        fn += int(((pred == 0) & (yb == 1)).sum().item())

    acc = correct / max(1, total)
    precision = tp / max(1, (tp + fp))
    recall = tp / max(1, (tp + fn))
    f1 = (2 * precision * recall) / max(1e-9, (precision + recall))
    loss_avg = loss_sum / max(1, total)

    return {"loss": loss_avg, "acc": acc, "precision": precision, "recall": recall, "f1": f1}


def train_epoch(model: nn.Module, loader: DataLoader, device: torch.device, opt: optim.Optimizer) -> float:
    model.train()
    crit = nn.CrossEntropyLoss()
    loss_sum = 0.0
    total = 0

    for xb, yb in loader:
        xb = xb.to(device)
        yb = yb.to(device)

        opt.zero_grad(set_to_none=True)
        logits = model(xb)
        loss = crit(logits, yb)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step()

        loss_sum += float(loss.item()) * yb.size(0)
        total += yb.size(0)

    return loss_sum / max(1, total)


def _make_balanced_sampler(rows: List[Row]) -> WeightedRandomSampler:
    # weights inversely proportional to class frequency
    counts = {0: 0, 1: 0}
    for r in rows:
        counts[r.label] += 1

    w0 = 1.0 / max(1, counts[0])
    w1 = 1.0 / max(1, counts[1])

    weights = [w1 if r.label == 1 else w0 for r in rows]
    return WeightedRandomSampler(weights=weights, num_samples=len(weights), replacement=True)


def _pick_default_csv(processed_dir: Path, name: str) -> Path:
    return processed_dir / name


def _resolve_csv(processed_dir: Path, csv_arg: Optional[str], fallback_name: str) -> Path:
    if csv_arg:
        p = Path(csv_arg)
        return p if p.is_absolute() else (Path.cwd() / p).resolve()
    return _pick_default_csv(processed_dir, fallback_name)


def _default_out_model(out_dir: Path, arch: str, tag: str) -> Path:
    safe_tag = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in (tag or "run"))
    safe_arch = (arch or "model").replace("/", "_")
    return out_dir / f"deepfake__{safe_arch}__{safe_tag}.pt"


def main() -> int:
    ap = argparse.ArgumentParser(description="Train deepfake detector on face-crops manifests.")
    ap.add_argument("--processed-dir", default="data/processed", help="Directory containing manifest_train.csv etc.")
    ap.add_argument("--train-csv", default=None, help="Optional path to train manifest CSV.")
    ap.add_argument("--val-csv", default=None, help="Optional path to val manifest CSV.")
    ap.add_argument("--test-csv", default=None, help="Optional path to test manifest CSV.")

    ap.add_argument("--arch", default="efficientnet_b0", help="efficientnet_b0..efficientnet_b7")
    ap.add_argument("--img-size", type=int, default=224, help="Input size (must match prepared faces).")

    ap.add_argument("--out-dir", default="models", help="Directory where to save checkpoints/reports.")
    ap.add_argument("--tag", default="run1", help="Suffix tag for output model name.")

    ap.add_argument("--out-model", default=None, help="(Optional) explicit checkpoint path. Overrides --out-dir/--tag.")
    ap.add_argument("--epochs", type=int, default=6)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--device", default="auto", help="auto|cpu|cuda")
    ap.add_argument("--num-workers", type=int, default=2)
    ap.add_argument("--no-balanced-sampler", action="store_true", help="Disable balanced sampler for training.")
    args = ap.parse_args()

    _seed(args.seed)

    if args.device == "cpu":
        device = torch.device("cpu")
    elif args.device == "cuda":
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    else:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    processed_dir = Path(args.processed_dir)
    train_csv = _resolve_csv(processed_dir, args.train_csv, "manifest_train.csv")
    val_csv = _resolve_csv(processed_dir, args.val_csv, "manifest_val.csv")
    test_csv = _resolve_csv(processed_dir, args.test_csv, "manifest_test.csv")

    train_rows = _read_manifest(train_csv)
    val_rows = _read_manifest(val_csv)
    test_rows = _read_manifest(test_csv)

    # Stats
    def stats(rows: List[Row]) -> Dict[str, int]:
        c0 = sum(1 for r in rows if r.label == 0)
        c1 = sum(1 for r in rows if r.label == 1)
        return {"real": c0, "fake": c1, "total": len(rows)}

    s_train = stats(train_rows)
    s_val = stats(val_rows)
    s_test = stats(test_rows)

    print("[DATA] train:", s_train, "|", str(train_csv))
    print("[DATA] val:  ", s_val,   "|", str(val_csv))
    print("[DATA] test: ", s_test,  "|", str(test_csv))

    train_ds = FaceDataset(train_rows, augment=True, img_size=int(args.img_size))
    val_ds = FaceDataset(val_rows, augment=False, img_size=int(args.img_size))
    test_ds = FaceDataset(test_rows, augment=False, img_size=int(args.img_size))

    if args.no_balanced_sampler:
        sampler = None
        shuffle = True
        drop_last = True
        print("[DATA] sampler: shuffle (no balanced sampler)")
    else:
        sampler = _make_balanced_sampler(train_rows)
        shuffle = False
        drop_last = True
        print("[DATA] sampler: balanced")

    train_loader = DataLoader(
        train_ds,
        batch_size=args.batch_size,
        sampler=sampler,
        shuffle=shuffle,
        num_workers=args.num_workers,
        pin_memory=(device.type == "cuda"),
        drop_last=drop_last,
    )
    val_loader = DataLoader(
        val_ds,
        batch_size=args.batch_size,
        shuffle=False,
        num_workers=args.num_workers,
        pin_memory=(device.type == "cuda"),
    )
    test_loader = DataLoader(
        test_ds,
        batch_size=args.batch_size,
        shuffle=False,
        num_workers=args.num_workers,
        pin_memory=(device.type == "cuda"),
    )

    model = build_model(args.arch).to(device)
    opt = optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.out_model:
        out_model = Path(args.out_model)
        if not out_model.is_absolute():
            out_model = (Path.cwd() / out_model).resolve()
        out_model.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_model = _default_out_model(out_dir, args.arch, args.tag)

    best_f1 = -1.0
    history = []

    for ep in range(1, args.epochs + 1):
        tr_loss = train_epoch(model, train_loader, device, opt)
        va = eval_epoch(model, val_loader, device)

        rec = {
            "epoch": ep,
            "train_loss": tr_loss,
            "val_loss": va["loss"],
            "val_acc": va["acc"],
            "val_precision": va["precision"],
            "val_recall": va["recall"],
            "val_f1": va["f1"],
        }
        history.append(rec)

        print(f"[E{ep}] train_loss={tr_loss:.4f} | val_loss={va['loss']:.4f} acc={va['acc']:.4f} f1={va['f1']:.4f}")

        if va["f1"] > best_f1:
            best_f1 = va["f1"]
            torch.save(
                {
                    "model_state": model.state_dict(),
                    "arch": str(args.arch),
                    "img_size": int(args.img_size),
                    "best_val_f1": float(best_f1),
                    "train_stats": s_train,
                    "val_stats": s_val,
                    "test_stats": s_test,
                    "history": history,
                    "manifests": {
                        "train_csv": str(train_csv),
                        "val_csv": str(val_csv),
                        "test_csv": str(test_csv),
                    },
                },
                out_model,
            )
            print(f"[OK] saved best checkpoint -> {out_model} (best_f1={best_f1:.4f})")

    # final test (reload best)
    ckpt = torch.load(out_model, map_location=device)
    model.load_state_dict(ckpt["model_state"])
    te = eval_epoch(model, test_loader, device)
    print(
        f"[TEST] loss={te['loss']:.4f} acc={te['acc']:.4f} f1={te['f1']:.4f} "
        f"precision={te['precision']:.4f} recall={te['recall']:.4f}"
    )

    # write training report json next to model
    report = {
        "device": str(device),
        "processed_dir": str(processed_dir),
        "train_csv": str(train_csv),
        "val_csv": str(val_csv),
        "test_csv": str(test_csv),
        "out_model": str(out_model),
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "lr": args.lr,
        "arch": str(args.arch),
        "img_size": int(args.img_size),
        "best_val_f1": float(best_f1),
        "final_test": te,
        "train_stats": s_train,
        "val_stats": s_val,
        "test_stats": s_test,
        "history": history,
    }
    rep_path = out_model.with_suffix(".training.json")
    rep_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[OK] wrote training report -> {rep_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
