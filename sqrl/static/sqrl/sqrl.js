$(function() {
  var sqrl_timeout = setInterval(function() {
    $.post(SQRL_CHECK_URL)
      .done(function(data) {
        console.log(data);
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
