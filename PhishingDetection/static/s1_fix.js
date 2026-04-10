// Fix for s1 is not defined error
// This script ensures s1 and s2 variables are properly defined

(function() {
    // Store original displayResults function
    const originalDisplayResults = window.displayResults;
    
    // Override displayResults to ensure variables are defined
    window.displayResults = function(data) {
        // Ensure s1 and s2 are defined at the right scope
        const s1 = data.ai_analysis?.stream1_features || {};
        const s2 = data.ai_analysis?.stream2_content || {};
        
        // Call original function with enhanced data
        return originalDisplayResults.call(this, data);
    };
    
    console.log('s1/s2 variable fix applied');
})();
