from tqdm import tqdm
import queue
from pwn import xor
whitelist = [151, 406, 409, 133, 32, 404, 370, 237, 244, 402, 246, 24, 201, 267, 281, 150, 278, 418, 158, 280, 236, 153, 33, 110, 372, 223, 25, 78, 31, 196, 72, 67, 198, 161, 285, 57, 326, 122, 320, 164, 143, 66, 358, 307, 117, 192, 334, 341, 64, 318, 376, 22, 61, 38, 332, 208, 179, 330, 238, 284, 367, 249, 351, 76, 93, 217, 197, 301, 165, 30, 155, 71, 70, 397, 124, 166, 68, 275, 215, 112, 29, 410, 324, 288, 395, 393, 206, 156, 349, 366, 387, 154, 322, 309, 187, 59, 313, 229, 311, 295, 232, 116, 379, 253, 227, 360, 362, 225, 400, 364, 241, 55, 190, 108, 299, 247, 75, 123, 277, 279, 355, 414, 412, 305, 286, 35, 365, 199, 316, 359, 149, 408, 240, 373, 139, 204, 43, 26, 328, 303, 413, 118, 34, 290, 106, 148, 405, 169, 202, 213, 99, 65, 274, 40, 416, 114, 319, 381, 248, 74, 82, 234, 80, 162, 47, 160, 282, 157, 235, 39, 69, 250, 121, 131, 194, 242, 259, 36, 219, 368, 28, 37, 283, 152, 120, 107, 291, 271, 276, 345, 383, 339, 159, 87, 374, 292, 97, 200, 115]
dp = [[[0 for x in range(64)] for x in range(440)] for i in range(201)] # 200 x 440 x 64 ([idx][score][traps])
prev = [[[[] for x in range(64)] for x in range(440)] for i in range(201)] # 200 x 440 x 64 ([idx][score][traps])
dp[0][22][63] = 1
toggles = [153, 187, 26, 235, 368, 383]
traps = [281, 280, 72, 76, 397, 156]
deltas = [-21, 1, 21, -1]
for idx in tqdm(range(1, 50*4 + 1)):
	for score in whitelist:
		for active in range(64):
			if score in traps and ((1 << traps.index(score)) & active):
				continue #death -> leave dp at 0
			prev_active = active
			if score in toggles:
				prev_active ^= 1 << toggles.index(score)
			for bits, d in enumerate(deltas):
				if 0 <= score - d < 440 and dp[idx-1][score-d][prev_active]:
					dp[idx][score][active] = 1
					prev[idx][score][active].append((idx-1, score-d, prev_active, bits))


print(dp[1][23])
print(dp[200][418])
xk = bytes.fromhex("094011E41C8192DB0B75266A2F7FDDD25221769FDF8E8FCD9F84613F6D7A871E2199C765DCC84A227D286469DC2034EDFBD7")

def dfs(idx, score, active, flag = b"", lastb = 0):
	if idx %4 == 0:
		flag += bytes([lastb])
		lastb = 0
	if idx == 0:
		print(xor(xk, flag))
		print(xor(xk, flag[::-1]))
		print(flag)
		exit(0)
	for l_idx, l_score, l_prev, l_bits in prev[idx][score][active]:
		dfs(l_idx, l_score, l_prev, flag, lastb<<2 | l_bits)

dfs(200, 418, 2)

# SEKAI{https://www.youtube.com/watch?v=J---aiyznGQ}
