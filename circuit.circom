pragma circom 2.0.0;

template OneHotVector(n) {
    signal input vector[n];
    signal output sum;
    var tempSum;
    
    // Initialize tempSum with first element
    tempSum = vector[0];
    
    // Calculate sum using intermediate variable
    for (var i = 1; i < n; i++) {
        tempSum = tempSum + vector[i];
    }
    
    // Assign final sum to the output signal
    sum <== tempSum;
    
    // Constraint: sum must be 1
    sum === 1;
    
    // Ensure each value is 0 or 1
    for (var i = 0; i < n; i++) {
        vector[i] * (vector[i] - 1) === 0;
    }
}

component main = OneHotVector(3);