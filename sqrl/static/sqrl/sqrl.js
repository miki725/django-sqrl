'use strict';

(function() {
  if (window.jQuery !== undefined) {
    // jQuery API Ajax is much more user-friendly
    // and handles browsers much better
    $(function() {
      var sqrl_timeout = setInterval(function() {
        $.post(SQRL_CHECK_URL)
          .done(function(data) {
            if (data.is_logged_in === true || data.redirect_to !== undefined) {
              clearTimeout(sqrl_timeout);
              if (data.redirect_to !== undefined) {
                window.location.href = data.redirect_to;
              }
            }
          })
          .fail(function() {
            clearInterval(sqrl_timeout);
          });
      }, 1500);
    });

  } else {
    // if jQuery is not found, then fallback to raw XHR use
    // which is not as reliable but works in most cases
    window.onload = function() {
      var sqrl_timeout = setInterval(function() {
        var request = new XMLHttpRequest();
        request.open('POST', SQRL_CHECK_URL, false);
        request.onreadystatechange = handleStateChange;

        function handleStateChange() {
          if (request.readyState === 4) {
            if (this.status === 200) {
              var data = JSON.parse(this.responseText);
              if (data.is_logged_in === true || data.redirect_to !== undefined) {
                clearTimeout(sqrl_timeout);
                if (data.redirect_to !== undefined) {
                  window.location.href = data.redirect_to;
                }
              }
            } else {
              clearInterval(sqrl_timeout);
            }
          }
        }

        try {
          request.send(null);
        } catch (exception) {
          clearInterval(sqrl_timeout);
        }
      }, 1500);
    }
  }
})();
