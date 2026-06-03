// ============================================================
// ChaCha20 Core — SCE for UCIe Die-to-Die Security
// IEEE MWSCAS 2026 — Submission 326
// RFC 7539 compliant — fixed endianness and round schedule
// ============================================================

module chacha20_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] key,
    input  wire [95:0]  nonce,
    input  wire [31:0]  counter,
    output reg  [511:0] keystream,
    output reg          valid
);

localparam C0 = 32'h61707865;
localparam C1 = 32'h3320646e;
localparam C2 = 32'h79622d32;
localparam C3 = 32'h6b206574;

reg [31:0] s [0:15];   // working state
reg [31:0] s0[0:15];   // initial state
reg [4:0]  round;
reg        running;

// Byte-swap 32-bit word (little-endian load)
function [31:0] bswap32;
    input [31:0] x;
    bswap32 = {x[7:0], x[15:8], x[23:16], x[31:24]};
endfunction

// Quarter round — pure combinational, applied to state regs
task qr;
    inout [31:0] a, b, c, d;
    begin
        a = a + b; d = d ^ a; d = {d[15:0], d[31:16]};
        c = c + d; b = b ^ c; b = {b[19:0], b[31:20]};
        a = a + b; d = d ^ a; d = {d[23:0], d[31:24]};
        c = c + d; b = b ^ c; b = {b[24:0], b[31:25]};
    end
endtask

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        valid   <= 0; running <= 0; round <= 0;
    end
    else if (start && !running) begin
        // Load per RFC 7539 Section 2.3 — little-endian words
        s[0]  <= C0; s[1] <= C1; s[2] <= C2; s[3] <= C3;
        s[4]  <= bswap32(key[255:224]);
        s[5]  <= bswap32(key[223:192]);
        s[6]  <= bswap32(key[191:160]);
        s[7]  <= bswap32(key[159:128]);
        s[8]  <= bswap32(key[127:96]);
        s[9]  <= bswap32(key[95:64]);
        s[10] <= bswap32(key[63:32]);
        s[11] <= bswap32(key[31:0]);
        s[12] <= counter;
        s[13] <= bswap32(nonce[95:64]);
        s[14] <= bswap32(nonce[63:32]);
        s[15] <= bswap32(nonce[31:0]);

        s0[0]  <= C0; s0[1] <= C1; s0[2] <= C2; s0[3] <= C3;
        s0[4]  <= bswap32(key[255:224]);
        s0[5]  <= bswap32(key[223:192]);
        s0[6]  <= bswap32(key[191:160]);
        s0[7]  <= bswap32(key[159:128]);
        s0[8]  <= bswap32(key[127:96]);
        s0[9]  <= bswap32(key[95:64]);
        s0[10] <= bswap32(key[63:32]);
        s0[11] <= bswap32(key[31:0]);
        s0[12] <= counter;
        s0[13] <= bswap32(nonce[95:64]);
        s0[14] <= bswap32(nonce[63:32]);
        s0[15] <= bswap32(nonce[31:0]);

        round <= 0; running <= 1; valid <= 0;
    end
    else if (running) begin
        if (round < 20) begin
            if (round[0] == 0) begin
                // Column round
                qr(s[0], s[4], s[8],  s[12]);
                qr(s[1], s[5], s[9],  s[13]);
                qr(s[2], s[6], s[10], s[14]);
                qr(s[3], s[7], s[11], s[15]);
            end else begin
                // Diagonal round
                qr(s[0], s[5], s[10], s[15]);
                qr(s[1], s[6], s[11], s[12]);
                qr(s[2], s[7], s[8],  s[13]);
                qr(s[3], s[4], s[9],  s[14]);
            end
            round <= round + 1;
        end else begin
            // Serialize output little-endian
            keystream <= {
                s[15]+s0[15], s[14]+s0[14],
                s[13]+s0[13], s[12]+s0[12],
                s[11]+s0[11], s[10]+s0[10],
                s[9]+s0[9], s[8]+s0[8],
                s[7]+s0[7], s[6]+s0[6],
                s[5]+s0[5], s[4]+s0[4],
                s[3]+s0[3], s[2]+s0[2],
                s[1]+s0[1], s[0]+s0[0]
            };
            valid <= 1; running <= 0; round <= 0;
        end
    end else begin
        valid <= 0;
    end
end

endmodule
