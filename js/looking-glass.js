function getCsrfToken() {
  return $('input[name="csrf_token"]').val() || '';
}

function request_doc(query) {
  // Validate query before making request
  if (!query || query.trim() === '') {
    return;
  }
  
  $.ajax({
    type: 'post',
    url: 'execute.php',
    data: { doc: query, dontlook: '', csrf_token: getCsrfToken() },
    dataType: 'json'
  }).done(function (response) {
    if (response && response.command) {
      $('#command-reminder').text(response.command);
      $('#description-help').html(response.description);
      $('#parameter-help').html(response.parameter);
    }
  }).fail(function (xhr) {
    // Silently fail - documentation is optional
    console.log('Cannot load documentation for:', query);
  });
}

function request_commands(routerID, datacenterID) {
  if (!routerID || routerID.trim() === '') {
    $("#query").html('');
    return;
  }
  
  var data = {selectedRouterValue: routerID, csrf_token: getCsrfToken()};
  if (datacenterID) {
    data.selectedDatacenterValue = datacenterID;
  }
  
  $.ajax({
    type: 'POST',
    url: 'execute.php',
    data: data
  }).done(function (response) {
    if (response && typeof response === 'object' && response.error) {
      console.error('Failed to load commands:', response.error);
      $('#error-text').text(response.error);
      $('.alert').slideDown();
      $("#query").html('');
      return;
    }

    if (!response || (typeof response === 'string' && response.trim() === '')) {
      $("#query").html('');
      return;
    }
    
    try {
      var response = $.parseHTML(response);
      $("#query").html(response);
      // Update help for the first command
      var firstCommand = $("#query option:first").val();
      if (firstCommand && firstCommand.trim() !== '') {
        request_doc(firstCommand);
      }
    } catch (e) {
      console.error('Error parsing command response:', e);
      $("#query").html('');
    }
  }).fail(function (xhr) {
    console.error('Failed to load commands:', xhr);
    $("#query").html('');
  });
}

function request_routers(datacenterID) {
  if (!datacenterID || datacenterID.trim() === '') {
    $("#routers").html('');
    $("#query").html('');
    return;
  }
  
  $.ajax({
    type: 'POST',
    url: 'execute.php',
    data: {selectedDatacenterValue: datacenterID, csrf_token: getCsrfToken()}
  }).done(function (response) {
    if (response && typeof response === 'object' && response.error) {
      console.error('Failed to load routers:', response.error);
      $('#error-text').text(response.error);
      $('.alert').slideDown();
      $("#routers").html('');
      $("#query").html('');
      return;
    }

    if (!response || (typeof response === 'string' && response.trim() === '')) {
      console.warn('Empty response when loading routers for datacenter:', datacenterID);
      $("#routers").html('');
      $("#query").html('');
      return;
    }
    
    try {
      var parsedResponse = $.parseHTML(response);
      $("#routers").html(parsedResponse);
      
      // After routers are loaded, load commands for the first router
      var firstRouter = $("#routers option:first").val();
      if (firstRouter && firstRouter.trim() !== '') {
        // Small delay to ensure DOM is updated
        setTimeout(function() {
          request_commands(firstRouter, datacenterID);
        }, 50);
      } else {
        // No routers found, clear commands
        $("#query").html('');
        console.warn('No routers found for datacenter:', datacenterID);
      }
    } catch (e) {
      console.error('Error parsing router response:', e, response);
      $("#routers").html('');
      $("#query").html('');
    }
  }).fail(function (xhr) {
    console.error('Failed to load routers:', xhr);
    $("#routers").html('');
    $("#query").html('');
    $('#help-content').text('Cannot load routers...');
  });
}

function stream_command(formData) {
  var params = new URLSearchParams(formData);
  var streamUrl = 'execute-stream.php?' + params.toString();
  var output = $('#output');
  var hadOutput = false;

  output.html('');
  $('#command_properties').attr('disabled', '');
  $('.alert').hide();
  $('.loading').show();

  var source = new EventSource(streamUrl);

  source.onmessage = function (event) {
    var payload;
    try {
      payload = JSON.parse(event.data);
    } catch (e) {
      $('#error-text').text('Unexpected streaming response.');
      $('.alert').slideDown();
      source.close();
      $('#command_properties').removeAttr('disabled');
      $('.loading').hide();
      return;
    }

    if (payload.type === 'error') {
      $('#error-text').text(payload.error || 'Streaming error.');
      $('.alert').slideDown();
      source.close();
      $('#command_properties').removeAttr('disabled');
      $('.loading').hide();
      return;
    }

    if (!hadOutput && (payload.type === 'command_start' || payload.type === 'output')) {
      $('.content').slideUp();
      $('.result').slideDown();
      hadOutput = true;
    }

    if (payload.html) {
      output.append(payload.html);
    }

    if (payload.type === 'done') {
      source.close();
      $('#command_properties').removeAttr('disabled');
      $('.loading').hide();
    }
  };

  source.onerror = function () {
    if (!hadOutput) {
      $('#error-text').text('Streaming connection failed.');
      $('.alert').slideDown();
    }
    source.close();
    $('#command_properties').removeAttr('disabled');
    $('.loading').hide();
  };
}

$(document).ready(function () {
  // hide the optional parameters field
  $('.result').hide();
  $('.loading').hide();
  $('.alert').hide();

  // close the alert bar
  $('.close').click(function () {
    $('.alert').slideUp();
  });

  // clear the form and page
  $('#clear').click(function (e) {
    $('.alert').slideUp();

    e.preventDefault();

    // reset the parameter field if it was marked as error
    $('#input-param').removeClass('is-invalid');

    // reset the form and update the doc modal
    $(this).closest('form').get(0).reset();
    request_doc($('#query').val());
    if (typeof grecaptcha !== "undefined" && typeof grecaptcha.reset === "function") {
      grecaptcha.reset();
    }
  });

  // reset the view to the default one
  $('#backhome').click(function () {
    $('.content').slideDown();
    $('.result').slideUp();
    if (typeof grecaptcha !== "undefined" && typeof grecaptcha.reset === "function") {
      grecaptcha.reset();
    }
  });

  // Initialize: load routers for the initially selected datacenter, then commands
  var initialDatacenter = $('#datacenters option:selected').val();
  if (initialDatacenter && initialDatacenter.trim() !== '') {
    // Load routers for the selected datacenter
    request_routers(initialDatacenter);
  } else {
    // No datacenters, try to load commands for initial router
    var initialRouter = $('#routers option:selected').val();
    if (initialRouter && initialRouter.trim() !== '') {
      request_commands(initialRouter, null);
    } else {
      // Initialize the help modal if no router selected, but only if query has a value
      var initialQuery = $('#query').val();
      if (initialQuery && initialQuery.trim() !== '') {
        request_doc(initialQuery);
      }
    }
  }

  // update help when a command is selected
  $('#query').on('change', function (e) {
    e.preventDefault();
    var selectedCommand = $('#query').val();
    if (selectedCommand && selectedCommand.trim() !== '') {
      request_doc(selectedCommand);
    }
  });

  // Update the router list when a datacenter is selected
  $('#datacenters').on('change', function (e) {
    e.preventDefault();
    e.stopImmediatePropagation();
    var datacenterID = $('#datacenters option:selected').val();
    if (datacenterID && datacenterID.trim() !== '') {
      request_routers(datacenterID);
    } else {
      // No datacenter selected, clear routers and commands
      $("#routers").html('');
      $("#query").html('');
    }
  });

  // Update the command list when a router is selected
  $('#routers').on('change', function (e) {
    e.preventDefault();
    e.stopImmediatePropagation();
    var routerID = $('#routers option:selected').val();
    var datacenterID = $('#datacenters option:selected').val();
    request_commands(routerID, datacenterID);
  });

  // if the field has been completed, turn it back to normal
  $('#input-param').change(function () {
    $('#input-param').removeClass('is-invalid');
  });

  // send an ajax request that will get the info on the router
  $('form').on('submit', function (e) {
    e.preventDefault();

    if (typeof EventSource !== 'undefined') {
      stream_command($('form').serialize());
      return;
    }

    $.ajax({
      type: 'post',
      url: 'execute.php',
      data: $('form').serialize(),
      beforeSend: function () {
        // show loading bar
        $('#command_properties').attr('disabled', '');
        $('.alert').hide();
        $('.loading').show();
      },
      complete: function () {
        // hide loading bar
        $('#command_properties').removeAttr('disabled');
        $('.loading').hide();
      }
    }).done(function (response) {
      // Commands that don't require parameters
      var noParameterCommands = ['speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb', 'system-info'];
      var selectedCommand = $('#query').val();
      var parameter = $('#input-param').val();
      
      if (response && typeof response === 'object' && response.error) {
        $('#error-text').text(response.error);
        $('.alert').slideDown();
        return;
      }

      if (!response || (typeof response === 'string' && response.length === 0)) {
        // Check if parameter is required for this command
        if (!noParameterCommands.includes(selectedCommand) && (!parameter || parameter.trim() === '')) {
          $('#error-text').text('No parameter given.');
          $('#input-param').focus().addClass('is-invalid');
          $('.alert').slideDown();
        } else {
          // Command doesn't require parameter, but got empty response
          $('#error-text').text('Empty response from server.');
          $('.alert').slideDown();
        }
      } else {
        if (typeof response === 'string') {
          try {
            response = $.parseJSON(response);
          } catch {
            $('#error-text').html("<pre>" + response + "</pre>");
            $('.alert').slideDown();
            return;
          }
        }

        if (response.error) {
          $('#error-text').text(response.error);
          $('.alert').slideDown();
        } else {
          $('#output').html(response.result);
          $('.content').slideUp();
          $('.result').slideDown();
        }
      }
    }).fail(function (xhr) {
      $('#error-text').text(xhr.responseText);
      $('.alert').slideDown();
    });
  });
});
