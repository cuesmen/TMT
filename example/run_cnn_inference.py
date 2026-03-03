import time
import torch
from torchvision.models import resnet18

model = resnet18(weights=None)
torch.set_num_threads(torch.get_num_threads())
torch.set_num_interop_threads(torch.get_num_threads())

model = resnet18(weights=None)
model.eval()

x = torch.randn(32, 3, 224, 224)

# Warmup
for _ in range(10):
    _ = model(x)

# Calibration
with torch.no_grad():
    t0 = time.time()
    iters = 20
    for _ in range(iters):
        _ = model(x)
    t1 = time.time()

per_iter = (t1 - t0) / iters
target_time = 30.0
target_iters = max(1, int(target_time / per_iter))

# Main run
t0 = time.time()
for _ in range(target_iters):
    _ = model(x)
t1 = time.time()

print(f"iters={target_iters} total={t1 - t0:.3f}s per_iter={per_iter:.4f}s")
