# Set the breakpoint at the desired address or function
b *decode+561

# Initialize a counter to track the number of iterations
set $counter = 0

# Command to execute when the breakpoint is hit
commands
  # Print the current iteration
  printf "Iteration: %d\n", $counter

  # Print the value of the EAX and EDX registers
  printf "Breakpoint hit. EAX: 0x%x, EDX: 0x%x\n", $eax, $edx

  # Increment the counter
  set $counter = $counter + 1

  # Stop after 33 iterations
  if $counter >= 33
    printf "Reached 33 iterations. Exiting.\n"
    detach
    quit
  end

  # Continue execution
  continue
end
