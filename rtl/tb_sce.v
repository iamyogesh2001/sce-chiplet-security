`timescale 1ns/1ps
module tb_sce;

reg         clk, rst_n, start;
reg [255:0] key;
reg [95:0]  nonce;
reg [31:0]  counter;
wire [511:0] keystream;
wire         valid;

chacha20_core dut (.clk(clk),.rst_n(rst_n),.start(start),
    .key(key),.nonce(nonce),.counter(counter),
    .keystream(keystream),.valid(valid));

always #5 clk = ~clk;

initial begin
    clk=0; rst_n=0; start=0;

    // RFC 7539 Section 2.3.2 — key as little-endian bytes
    // key bytes: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
    //            10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
    // In Verilog [255:0] MSB first:
    key     = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
    // nonce bytes: 00 00 00 09 00 00 00 4a 00 00 00 00
    nonce   = 96'h000000090000004a00000000;
    counter = 32'd1;

    @(posedge clk); #1; rst_n=1;
    @(posedge clk); #1; start=1;
    @(posedge clk); #1; start=0;
    wait(valid); @(posedge clk);

    $display("==============================================");
    $display("  RFC 7539 Section 2.3.2 Test Vector");
    $display("==============================================");
    $display("  Word 0: 0x%08h (exp: 0xe4e7f110)", keystream[31:0]);
    $display("  Word 1: 0x%08h (exp: 0x15593bd1)", keystream[63:32]);
    $display("  Word 2: 0x%08h (exp: 0x1fdd0f50)", keystream[95:64]);
    $display("  Word 3: 0x%08h (exp: 0xc47120a3)", keystream[127:96]);

    if (keystream[31:0]==32'he4e7f110 && keystream[63:32]==32'h15593bd1 &&
        keystream[95:64]==32'h1fdd0f50 && keystream[127:96]==32'hc47120a3)
        $display("  RESULT: PASS");
    else
        $display("  RESULT: FAIL");

    // All-zero vector RFC 7539 Section 2.1.1
    key=256'h0; nonce=96'h0; counter=32'h0;
    @(posedge clk); #1; start=1;
    @(posedge clk); #1; start=0;
    wait(valid); @(posedge clk);

    $display("==============================================");
    $display("  All-zero Test Vector");
    $display("==============================================");
    $display("  Word 0: 0x%08h (exp: 0xade0b876)", keystream[31:0]);
    if (keystream[31:0]==32'hade0b876)
        $display("  RESULT: PASS");
    else
        $display("  RESULT: FAIL");

    $display("==============================================");
    $finish;
end

initial begin #200000; $display("TIMEOUT"); $finish; end
endmodule
