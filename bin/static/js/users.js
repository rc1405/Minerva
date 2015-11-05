/*
    Copyright (C) 2015  Ryan M Cote.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

    Author: Ryan M Cote <minervaconsole@gmail.com>
*/
var minerva = minerva || {};

minerva.users = {};

(function ($, app) {
  // declare module properties
  app.selected = [];  
  app.nav = $('nav');
  app.form = $('form');
  app.table = $('#event_table tbody');
  app.form_type = $('#form_type').val();
  app.csrf_token = $('#csrf_token').val();
  
  // declare module functions
  app.clearSelected = function() {
    app.table.children('tr.minerva-active').removeClass('minerva-active');
    app.selected = [];
  };
  
  app.startTrack = function(e) {
    var row = $(e.currentTarget);
    var id = row.data('id');
    
    if (row.hasClass('minerva-active')) {
      app.resetUser();
    } else {
      if (app.selected.length) {
        app.clearSelected();
      }
      row.addClass('minerva-active');
      app.selected.push(id);
      app.editUser();
    }
    
    e.stopPropagation();
  };
  
  app.subUser = function() {
    if (app.selected.length) {
      if ($('#password').val().length < 1) {
        var req_type = 'updatePerms';
      } else {
        var req_type = 'editUser';
      }
    } else {
      var req_type = 'new_user';
    }
    var data = {
      csrf_token: app.csrf_token,
      username: '',
      password: '',
      console: 'false',
      responder: 'false',
      sensor_admin: 'false',
      user_admin: 'false',
      server_admin: 'false',
      updateType: req_type,
      enabled: 'false',
    };
    $.each($('form').serializeArray(), function(i, item) {
      data[item.name] = item.value;
    });
    if (data['username'].length < 4) {
      alert('Username is too short');
      return;
    };
    $.ajax({
      method: 'POST',
      url: '/users',
      data: JSON.stringify(data),
      contentType: 'application/json',
      headers: {
        csrfmiddlewaretoken: app.csrf_token
      },
      success: function (data) {
        alert(data);
        if (data == 'Success') {
          location='/users';
        };
      },
    });
  };
  app.resetUser = function() {
    app.clearSelected();
    $("#username").val('');
    $("#password").val('');
    $("#console").prop('checked', true);
    $("#responder").prop('checked', false);
    $("#sensor_admin").prop('checked', false);
    $("#user_admin").prop('checked', false);
    $("#server_admin").prop('checked', false);
    $("#enabled").prop('checked', true);
    $("#enabled").prop('disabled', true);
  };

  app.editUser = function() {
    var row = app.table.children('tr.minerva-active');
    var id = row.data('id');
    $("#username").val(row.find("td:first").html());
    $("#console").prop('checked', $("#console" + id).prop('checked'));
    $("#responder").prop('checked', $("#responder" + id).prop('checked'));
    $("#sensor_admin").prop('checked', $("#sensor_admin" + id).prop('checked'));
    $("#user_admin").prop('checked', $("#user_admin" + id).prop('checked'));
    $("#server_admin").prop('checked', $("#server_admin" + id).prop('checked'));
    $("#enabled").prop('checked', $("#enabled" + id).prop('checked'));
    $("#enabled").prop('disabled', false);
  };
  
  // bind events
  app.table.on('click', 'tr', app.startTrack);
  app.form.find('#minerva-subUser').click(app.subUser);
  app.form.find('#minerva-resetUser').click(app.resetUser);
  
})(jQuery, minerva.users);
