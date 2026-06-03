// ============================================================
// SCE Top-Level — Secure Communication Engine
// UCIe Die-to-Die Security — IEEE MWSCAS 2026
// Integrates: ChaCha20 keystream + Poly1305 MAC + encrypt XOR
// ============================================================

module sce_top (
    input  wire          clk,
    input  wire          rst_n,

    // Key material (from Session Manager / RoT)
    input  wire [255:0]  session_key,   // ChaCha20 key
    input  wire [95:0]   nonce,         // 96-bit nonce
    input  wire [31:0]   pkt_counter,   // packet sequence number
    input  wire [255:0]  mac_key,       // Poly1305 one-time key

    // Plaintext input
    input  wire          pkt_valid,     // new packet to encrypt
    input  wire [511:0]  plaintext,     // 512-bit payload block
    input  wire          last_block,    // final block of packet

    // Encrypted output
    output wire [511:0]  ciphertext,    // encrypted payload
    output wire [127:0]  auth_tag,      // Poly1305 auth tag
    output wire          output_valid   // ciphertext + tag ready
);

// ─── INTERNAL SIGNALS ──────────────────────────────────────
wire [511:0] keystream;
wire         ks_valid;
wire [127:0] mac_tag;
wire         mac_valid;

reg          chacha_start;
reg          poly_start;
reg          poly_block_valid;
reg  [511:0] ct_reg;

// ─── CHACHA20 INSTANCE ─────────────────────────────────────
chacha20_core u_chacha20 (
    .clk        (clk),
    .rst_n      (rst_n),
    .start      (chacha_start),
    .key        (session_key),
    .nonce      (nonce),
    .counter    (pkt_counter),
    .keystream  (keystream),
    .valid      (ks_valid)
);

// ─── POLY1305 INSTANCE ─────────────────────────────────────
poly1305_core u_poly1305 (
    .clk         (clk),
    .rst_n       (rst_n),
    .start       (poly_start),
    .block_valid (poly_block_valid),
    .last_block  (last_block),
    .block_in    (ct_reg[127:0]),   // feed ciphertext blocks
    .key         (mac_key),
    .tag         (mac_tag),
    .tag_valid   (mac_valid)
);

// ─── ENCRYPT: XOR plaintext with keystream ─────────────────
assign ciphertext  = ct_reg;
assign auth_tag    = mac_tag;
assign output_valid = mac_valid;

// ─── CONTROL FSM ───────────────────────────────────────────
always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        chacha_start     <= 1'b0;
        poly_start       <= 1'b0;
        poly_block_valid <= 1'b0;
        ct_reg           <= 512'd0;
    end
    else begin
        chacha_start     <= 1'b0;
        poly_start       <= 1'b0;
        poly_block_valid <= 1'b0;

        if (pkt_valid) begin
            // Trigger ChaCha20 keystream generation
            chacha_start <= 1'b1;
            // Start Poly1305 for this packet
            poly_start   <= 1'b1;
        end

        if (ks_valid) begin
            // XOR plaintext with keystream to produce ciphertext
            ct_reg           <= plaintext ^ keystream;
            // Feed ciphertext to Poly1305
            poly_block_valid <= 1'b1;
        end
    end
end

endmodule
