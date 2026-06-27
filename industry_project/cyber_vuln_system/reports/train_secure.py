import os
import pandas as pd
from PIL import Image, ImageFile
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from torchvision import transforms, models
from sklearn.model_selection import train_test_split
import signal

if torch.cuda.is_available():
    device = torch.device("cuda")
elif torch.backends.mps.is_available():
    device = torch.device("mps")
else:
    device = torch.device("cpu")

print("Using device:", device)

BASE_DIR = "/run/media/Hiren/MyUSB/Dataset/"

ImageFile.LOAD_TRUNCATED_IMAGES = True

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("Image load timeout")

signal.signal(signal.SIGALRM, timeout_handler)

def safe_load_image(path, timeout=1):
    try:
        signal.alarm(timeout)
        with Image.open(path) as img:
            img.load()
            signal.alarm(0)
            return img.convert("RGB")
    except TimeoutException:
        print(f"⏰ TIMEOUT — Skipping: {path}")
        return Image.new("RGB", (224, 224))
    except Exception as e:
        print(f"❌ BAD IMAGE: {path} — {e}")
        return Image.new("RGB", (224, 224))
    finally:
        signal.alarm(0)

class AIDataset(Dataset):
    def __init__(self, df, transform=None):
        self.df = df.reset_index(drop=True)
        self.transform = transform

    def __len__(self):
        return len(self.df)

    def __getitem__(self, idx):
        row = self.df.iloc[idx]
        img_path = os.path.join(BASE_DIR, row["file_name"])
        label = row["label"]

        if idx % 500 == 0:
            print("Loading image:", img_path)

        image = safe_load_image(img_path)

        if self.transform:
            image = self.transform(image)

        return image, torch.tensor(label, dtype=torch.float32)

train_df = pd.read_csv(os.path.join(BASE_DIR, "train.csv"))
print("Loaded CSV records:", len(train_df))

train_df, val_df = train_test_split(
    train_df,
    test_size=0.2,
    random_state=42,
    stratify=train_df["label"]
)

print("Train size:", len(train_df))
print("Validation size:", len(val_df))

train_transform = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.RandomHorizontalFlip(),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406],
                         std=[0.229, 0.224, 0.225])
])

val_transform = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406],
                         std=[0.229, 0.224, 0.225])
])

train_dataset = AIDataset(train_df, train_transform)
val_dataset = AIDataset(val_df, val_transform)

train_loader = DataLoader(train_dataset, batch_size=16, shuffle=True, num_workers=0)
val_loader = DataLoader(val_dataset, batch_size=16, shuffle=False, num_workers=0)

print("\nDataLoaders ready.")

model = models.resnet18(weights=models.ResNet18_Weights.IMAGENET1K_V1)
num_features = model.fc.in_features
model.fc = nn.Linear(num_features, 1)

model = model.to(device)
print("ResNet-18 loaded.\n")

criterion = nn.BCEWithLogitsLoss()
optimizer = torch.optim.Adam(model.parameters(), lr=1e-4)

EPOCHS = 5

print("\n==== TRAINING START ====\n")

for epoch in range(EPOCHS):
    model.train()
    train_loss = 0
    print(f"\n--- Epoch {epoch+1}/{EPOCHS} ---")

    for batch_idx, (images, labels) in enumerate(train_loader):
        print(f"Batch {batch_idx+1}/{len(train_loader)}", end="\r")

        images = images.to(device)
        labels = labels.to(device).unsqueeze(1)

        optimizer.zero_grad()
        outputs = model(images)
        loss = criterion(outputs, labels)

        loss.backward()
        optimizer.step()
        train_loss += loss.item()

    # Validation
    model.eval() # Set model to evaluation mode
    val_loss = 0
    correct = 0
    total = 0

    with torch.no_grad():
        for images, labels in val_loader:
            images = images.to(device)
            labels = labels.to(device).unsqueeze(1)

            outputs = model(images)
            loss = criterion(outputs, labels)
            val_loss += loss.item()

            preds = (torch.sigmoid(outputs) > 0.5).float()
            correct += (preds == labels).sum().item()
            total += labels.size(0)

    print(f"\nEpoch {epoch+1} Summary:")
    print(f"Train Loss: {train_loss/len(train_loader):.4f}")
    print(f"Val Loss:   {val_loss/len(val_loader):.4f}")
    print(f"Val Acc:    {correct/total:.4f}")

MODEL_PATH = "resnet18_ai_classifier.pth"
torch.save(model.state_dict(), MODEL_PATH)

print(f"\n🎉 Model saved as: {MODEL_PATH}")
