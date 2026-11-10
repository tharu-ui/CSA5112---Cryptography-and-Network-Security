class ESPReceiverState:
    def __init__(self, window_size=32):
        self.window_size = window_size
        self.highest_seq = 0
        self.window_bitmap = 0  # Bitmask representing received packets within the window

    def process_packet(self, seq_num, icv_valid):
        print(f"\n[IPSEC ESP] Incoming Packet -> Seq: {seq_num}, ICV Valid: {icv_valid}")
        
        # 1. Verify ICV first
        if not icv_valid:
            print("[DROP] Reason: ICV Integrity Check Failed.")
            return "DROP"

        # 2. Anti-Replay Check & Window Logic
        if seq_num > self.highest_seq:
            # Advance window
            shift = seq_num - self.highest_seq
            if shift >= self.window_size:
                self.window_bitmap = 1
            else:
                self.window_bitmap = (self.window_bitmap << shift) | 1
            self.highest_seq = seq_num
            print(f"[ACCEPT] Packet is newer than Highest. New Highest: {self.highest_seq}")
            return "ACCEPT"
        
        diff = self.highest_seq - seq_num
        if diff >= self.window_size:
            print("[DROP] Reason: Packet is too old (outside window). Replay or excessive delay.")
            return "DROP"
            
        # Inside window check
        mask = 1 << diff
        if (self.window_bitmap & mask) != 0:
            print("[DROP] Reason: Packet already received (Replay detected).")
            return "DROP"
        
        # Mark as received
        self.window_bitmap |= mask
        print(f"[ACCEPT] Packet within window accepted at offset {diff}.")
        return "ACCEPT"

if __name__ == "__main__":
    esp = ESPReceiverState(window_size=4)
    stream = [(1, True), (2, True), (5, True), (3, True), (2, True), (9, True), (7, False), (7, True)]
    for seq, icv in stream:
        esp.process_packet(seq, icv)