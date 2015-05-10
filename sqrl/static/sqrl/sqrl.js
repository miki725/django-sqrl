'use strict';

(function() {
  var next_input     = document.querySelectorAll('input[name="next"]'),
      next_url       = next_input.length > 0 ? next_input[0].value : null,
      current_url    = window.location.href,
      sqrl_frequency = 1500,
      sqrl_call      = function() {
        setTimeout(sqrl_handler, sqrl_frequency);
      },
      sqrl_handler   = function() {
        var request = new XMLHttpRequest(),
            url     = SQRL_CHECK_URL + '?url=';

        if (next_url !== null) {
          url = url + encodeURIComponent('?next=' + next_url);
        } else {
          url = url + encodeURIComponent(current_url);
        }

        request.open('POST', url, false);
        request.onreadystatechange = handleStateChange;

        function handleStateChange() {
          if (request.readyState === 4) {
            if (this.status === 200) {
              var data = JSON.parse(this.responseText);
              if (data.is_logged_in === true || data.redirect_to !== undefined) {
                if (data.redirect_to !== undefined) {
                  window.location.href = data.redirect_to;
                }
              } else {
                sqrl_call();
              }
            }
          }
        }

        try {
          request.send(null);
        } catch (exception) {
          // do not send anymore requests if error occurred
        }
      };

  window.onload = sqrl_handler;

})();
