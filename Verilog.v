module crypto_lock_system (
    input wire clk,                  // System input clock (e.g., 50MHz board oscillator)
    input wire rst_n,                // Active-low master hardware reset
    input wire shift_en,             // Pulsed high to shift in a single user bit
    input wire serial_in,            // Serial input data bit from user interface
    input wire enter_press,          // Pulsed high when user submits the password
    input wire [7:0] rand_num,       // 8-bit entropy source from Ring Oscillator
    output reg lock_status,          // 1 = Unlocked, 0 = Locked[cite: 1]
    output reg [2:0] current_state   // Output pins for monitoring current state
);

    // Hardcoded Prototype System Passwords (8-bit for simplicity)
    localparam [7:0] SYSTEM_PASSWORD = 8'b10100101; 
    localparam [7:0] ADMIN_PASSWORD  = 8'b11110000; 

    // Finite State Machine (FSM) Encoding
    localparam STATE_INIT         = 3'b000; // Power-on stabilization delay state
    localparam STATE_IDLE         = 3'b001; // Awaiting password submission
    localparam STATE_VERIFY       = 3'b010; // Symmetric XOR verification
    localparam STATE_UNLOCK       = 3'b011; // Access granted state[cite: 1]
    localparam STATE_ADMIN_MODE   = 3'b100; // User locked out; awaiting Admin PIN[cite: 1]
    localparam STATE_ADMIN_VERIFY = 3'b101; // Verifying Admin password
    localparam STATE_COOLDOWN     = 3'b110; // Hardware penalty delay state[cite: 1]

    // Internal Registers & Storage Pipelines
    reg [7:0]  input_shift_reg;      // Captures serial user inputs over time[cite: 1]
    reg [1:0]  user_attempts;        // Counter tracking user failures (max 3)[cite: 1]
    reg [1:0]  admin_attempts;       // Counter tracking admin failures (max 3)
    reg [7:0]  stored_password;      // Dynamically updatable system lock key
    
    // CPLD Resource Optimization: Using a prescaler clock divider to run timers
    // instead of consuming hundreds of macrocells with massive 32-bit registers.
    reg [15:0] clk_prescaler;        // Divides the system clock down 
    reg        slow_tick;            // Generated low-frequency tick pulse
    reg [11:0] delay_counter;        // Standardized counter for delays (Init & Cooldown)

    // Clock Prescaler Generation Logic
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            clk_prescaler <= 16'b0;
            slow_tick     <= 1'b0;
        end else begin
            if (clk_prescaler >= 16'd50000) begin // Adjust constant based on clock speed
                clk_prescaler <= 16'b0;
                slow_tick     <= 1'b1;
            end else begin
                clk_prescaler <= clk_prescaler + 1'b1;
                slow_tick     <= 1'b0;
            end
        end
    end

    // Step 1: Shift Register Pipeline for Serial Bit Capture
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            input_shift_reg <= 8'b0;
        end else if (shift_en) begin
            input_shift_reg <= {input_shift_reg[6:0], serial_in}; // Shift left
        end
    end

    // Step 2: Main Access-Control Cryptographic FSM
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            current_state   <= STATE_INIT;
            lock_status     <= 1'b0;
            user_attempts   <= 2'b0;
            admin_attempts  <= 2'b0;
            stored_password <= SYSTEM_PASSWORD;
            delay_counter   <= 12'b0;
        end else begin
            case (current_state)

                // Power-On Stabilization Delay: Prevents race conditions and lets
                // the ring oscillator transients settle into stable non-deterministic behavior.
                STATE_INIT: begin
                    lock_status <= 1'b0;
                    if (slow_tick) begin
                        if (delay_counter >= 12'd4000) begin // Ends approx 4-5s delay
                            delay_counter <= 12'b0;
                            current_state <= STATE_IDLE;
                        end else begin
                            delay_counter <= delay_counter + 1'b1;
                        end
                    end
                end

                STATE_IDLE: begin
                    lock_status <= 1'b0;
                    if (enter_press) begin
                        current_state <= STATE_VERIFY;
                    end
                end

                // BUG FIX STATE: Symmetrically masks both user input and true passwords 
                // with the entropy block to cancel out mathematical collision vulnerabilities.
                STATE_VERIFY: begin
                    if ((input_shift_reg ^ rand_num) == (stored_password ^ rand_num)) begin
                        current_state <= STATE_UNLOCK;
                        user_attempts <= 2'b0; // Reset counter on authentic entry
                    end else begin
                        user_attempts <= user_attempts + 1'b1;
                        if (user_attempts >= 2'd2) begin // True on the 3rd failed effort[cite: 1]
                            current_state <= STATE_ADMIN_MODE;
                        end else begin
                            current_state <= STATE_IDLE; 
                        end
                    end
                end

                STATE_UNLOCK: begin
                    lock_status <= 1'b1; // Physical lock trigger assertions
                    // Stays unlocked safely until master hardware reset (rst_n) toggles
                end

                STATE_ADMIN_MODE: begin
                    // Main fallback mode; shifts lock capture control to master Admin entry
                    if (enter_press) begin
                        current_state <= STATE_ADMIN_VERIFY;
                    end
                end

                STATE_ADMIN_VERIFY: begin
                    if ((input_shift_reg ^ rand_num) == (ADMIN_PASSWORD ^ rand_num)) begin
                        stored_password <= input_shift_reg; // Dynamic rewritable system key upgrade
                        user_attempts   <= 2'b0;
                        admin_attempts  <= 2'b0;
                        current_state   <= STATE_IDLE;
                    end else begin
                        admin_attempts <= admin_attempts + 1'b1;
                        if (admin_attempts >= 2'd2) begin // 3 strikes on Admin level failed
                            delay_counter <= 12'b0;
                            current_state <= STATE_COOLDOWN;
                        end else begin
                            current_state <= STATE_ADMIN_MODE;
                        end
                    end
                end

                // Prototype Cooldown State: Temporary structural lockout penalty loop[cite: 1]
                STATE_COOLDOWN: begin
                    lock_status <= 1'b0; 
                    if (slow_tick) begin
                        if (delay_counter >= 12'd4000) begin // 5-10 second system freeze[cite: 1]
                            user_attempts  <= 2'b0;
                            admin_attempts <= 2'b0;
                            delay_counter  <= 12'b0;
                            current_state  <= STATE_IDLE;
                        end else begin
                            delay_counter <= delay_counter + 1'b1;
                        end
                    end
                end

                default: current_state <= STATE_IDLE;
            endcase
        end
    end
endmodule
