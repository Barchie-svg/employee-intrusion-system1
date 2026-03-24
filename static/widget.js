(function() {
    // Intrusion Detection System Embed Widget
    
    // Determine the host dynamically based on where this script is loaded from
    // That means if you deploy to https://my-app.onrender.com, it will use that domain!
    const host = new URL(document.currentScript.src).origin;
    
    // Create iframe element
    const iframe = document.createElement('iframe');
    iframe.src = host + '/embed/login';
    iframe.style.width = '100%';
    iframe.style.border = 'none';
    iframe.style.minHeight = '450px';
    iframe.style.overflow = 'hidden';
    iframe.style.background = 'transparent';
    iframe.setAttribute('allowtransparency', 'true');
    iframe.setAttribute('title', 'Intrusion Detection Login Widget');
    
    // Find where the script was inserted and insert iframe right there
    const scriptTag = document.currentScript;
    scriptTag.parentNode.insertBefore(iframe, scriptTag);
    
    // Listen for resize messages from iframe so it seamlessly fits on the customer page
    window.addEventListener('message', function(e) {
        // Only accept messages from our backend
        if (e.origin !== host) return;
        
        if (e.data && e.data.type === 'ids-widget-height') {
            iframe.style.height = e.data.height + 'px';
        }
    });

    console.log("Intrusion Detection System Widget Successfully Loaded!");
})();
