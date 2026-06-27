import torch
import torch.nn as nn
from torchvision import transforms, models
from PIL import Image
import os

MODEL_PATH = "/home/Hiren/Documents/Cache/News-Verifier/resnet18_ai_classifier.pth"

_device = "cuda" if torch.cuda.is_available() else "cpu"
_model = None

def _load_model():
    global _model
    if _model is None:
        print("Loading model from:", MODEL_PATH)

        model = models.resnet18(weights=None)
        num_features = model.fc.in_features
        model.fc = nn.Linear(num_features, 1)

        # Load state dict with error handling for missing file
        try:
            model.load_state_dict(torch.load(MODEL_PATH, map_location=_device))
        except FileNotFoundError:
            print(f"ERROR: Model file not found at {MODEL_PATH}")
            return
        except Exception as e:
            print(f"ERROR: Failed to load model state dict: {e}")
            return

        model.to(_device)
        model.eval() # Set model to evaluation mode
        _model = model

_transform = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406],
                         std=[0.229, 0.224, 0.225])
])

def classify_image(image_path):
    _load_model()
    # Check if model loading failed
    if _model is None:
        return "ERROR: Model could not be loaded."

    if not os.path.exists(image_path):
        return "ERROR: File not found."

    try:
        img = Image.open(image_path).convert("RGB")
        img_tensor = _transform(img).unsqueeze(0).to(_device)

        with torch.no_grad():
            output = _model(img_tensor)
            sig = torch.sigmoid(output).item()

        print(sig)
        if sig < 0.5:
            return "REAL"
        else:
            return "AI Generated"
    except Exception as e:
        print(f"ERROR: An error occurred during image classification: {e}")
        return "ERROR: Image processing failed."