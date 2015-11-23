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

minerva.filters = {};

(function ($, app) {
  // declare module properties
  app.selected = [];  
  app.nav = $('nav');
  app.changeType = $('#filter_select');
  app.actionType = $('#action_select');
  app.applyType = $('#apply_select');
  app.table = $('#event_table tbody');
  app.application = $('#current_status');
  //app.form_type = $('#form_type').val();
  app.csrf_token = $('#csrf_token').val();
  
  app.clearSelected = function() {
    app.table.children('tr.minerva-active').removeClass('minerva-active');
    app.selected = [];
  };

  app.startTrack = function(e) {
    var row = $(e.currentTarget);
    var id = row.data('id');
    
    if (row.hasClass('minerva-active')) {
      row.removeClass('minerva-active');
      app.selected.splice(app.selected.indexOf(id), 1);
    } else {
      row.addClass('minerva-active');
      app.selected.push(id);
    }
    
    e.stopPropagation();
  };

  app.getData = function(filter_type) {
    var data = {};
    if (filter_type == 'signature') {
      if (!$.isNumeric($('#sig_id').val())) {
        alert('Invalid SID');
        alert($('#sig_id').val());
      } else if (!$.isNumeric($('#rev').val())) {
        alert('Invalid Revision');
      } else if (!$.isNumeric($('#gid').val())) {
        alert('Invalid GID');
      } else {
        data['sig_id'] = $('#sig_id').val();
        data['rev'] = $('#rev').val();
        data['gid'] = $('#gid').val();
        return data;
      };
    } else if ( filter_type == 'category') {
      data['category'] = $('#classification').val();
      return data;
    } else if ( filter_type == 'address' ) {
      if ($('#ip_address').val().length == 0) {
        alert('No Ip Address entered');
      } else {
        data['ip_address'] = $('#ip_address').val();
        return data;
      }
    } else if ( filter_type == 'session' ) {
      if ($('#src_ip').val().length == 0) {
        alert('No Source IP Address entered');
      } else if ($('#dest_ip').val().length == 0) {
        alert('No Destination IP Address entered');
      } else {
        data['src_ip'] = $('#src_ip').val();
        data['dest_ip'] = $('#dest_ip').val();
        return data;
      }
    } else if ( filter_type == 'sig_address' ) {
      if (!$.isNumeric($('#sig_id').val())) {
        alert('Invalid SID');
      } else if (!$.isNumeric($('#rev').val())) {
        alert('Invalid Revision');
      } else if (!$.isNumeric($('#gid').val())) {
        alert('Invalid GID');
      } else if ($('#ip_address').val().length == 0) {
        alert('No IP Address entered');
      } else {
        data['sig_id'] = $('#sig_id').val();
        data['rev'] = $('#rev').val();
        data['gid'] = $('#gid').val();
        data['ip_address'] = $('#ip_address').val();
        return data;
      };
    } else if ( filter_type == 'sig_session' ) {
      if (!$.isNumeric($('#sig_id').val())) {
        alert('Invalid SID');
      } else if (!$.isNumeric($('#rev').val())) {
        alert('Invalid Revision');
      } else if (!$.isNumeric($('#gid').val())) {
        alert('Invalid GID');
      } else if ($('#src_ip').val().length == 0) {
        alert('No Source IP Address Entered');
      } else if ($('#dest_ip').val().length == 0) {
        alert('No Destination IP Address Entered');
      } else {
        data['sig_id'] = $('#sig_id').val();
        data['rev'] = $('#rev').val();
        data['gid'] = $('#gid').val();
        data['src_ip'] = $('#src_ip').val();
        data['dest_ip'] = $('#dest_ip').val();
        return data;
      };
    };
    return {};
  };

  app.FilterChanges = function(e) {
    var action = $(e.target).data('action');

    if (app.selected.length) {

      var data = {
        events: app.selected,
        formType: app.form_type,
        req_type: action,
        application: $('#action_select').val(),
      };

      $.ajax({
        method: 'POST',
        url: '/event_filters',
        data: JSON.stringify(data),
        contentType: 'application/json',
        headers: {
          csrfmiddlewaretoken: app.csrf_token
        },
        success: function () {
          location='/event_filters';
        },
      });
    } else {
      alert('No filters selected');
    };
  };
  
  app.getAction = function(data) {
    if ($('#action_select').val() == 'STATUS') {
      data['action_type'] = 'STATUS';
      data['action_value'] = $('#STATUS').val();
    } else if ($('#action_select').val() == 'priority') {
      data['action_type'] = 'priority';
      data['action_value'] = $('#priority').val();
      data['priority_op'] = $('#priority_op').val();
    } else {
      alert('No Action Selected');
    }
    return data;
  };

  app.addFilter = function() {
    var data = app.getData($('#filter_select').val());
    if (Object.keys(data).length > 0) {
      data['type'] = $('#filter_select').val();
      data['req_type'] = 'new_filter';
      data = app.getAction(data);
      if ('action_type' in data) {
          data['application'] = $('#apply_select').val();
          data['formType'] = app.form_type;
          if (data['application'] == 'existing' || data['application'] == 'both') {
            data['ApplyTo'] = app.application.val();
          };
          $.ajax({
            method: 'POST',
            url: '/event_filters',
            data: JSON.stringify(data),
            contentType: 'application/json',
            headers: {
              csrfmiddlewaretoken: app.csrf_token
            },
            success: function () {
              location='/event_filters';
            },
          });
      };
    };
  };

  app.formMod = function() {
    active = app.changeType.val();
    if (active == 'signature') {
      $('#signature').removeClass('hidden');
      $('#category').addClass('hidden');
      $('#address').addClass('hidden');
      $('#session').addClass('hidden');
    } else if ( active == 'category') {
      $('#signature').addClass('hidden');
      $('#category').removeClass('hidden');
      $('#address').addClass('hidden');
      $('#session').addClass('hidden');
    } else if ( active == 'address' ) {
      $('#signature').addClass('hidden');
      $('#category').addClass('hidden');
      $('#address').removeClass('hidden');
      $('#session').addClass('hidden');
    } else if ( active == 'session' ) {
      $('#signature').addClass('hidden');
      $('#category').addClass('hidden');
      $('#address').addClass('hidden');
      $('#session').removeClass('hidden');
    } else if ( active == 'sig_address' ) {
      $('#signature').removeClass('hidden');
      $('#category').addClass('hidden');
      $('#address').removeClass('hidden');
      $('#session').addClass('hidden');
    } else if ( active == 'sig_session' ) {
      $('#signature').removeClass('hidden');
      $('#category').addClass('hidden');
      $('#address').addClass('hidden');
      $('#session').removeClass('hidden'); 
    };
  };
 
  app.actionMod = function() {
    active = app.actionType.val();
    if (active == 'STATUS' ) {
      $('#change_status').removeClass('hidden');
      $('#change_priority').addClass('hidden');
    } else if ( active == 'priority' ) {
      $('#change_status').addClass('hidden');
      $('#change_priority').removeClass('hidden');
    } else {
      $('#change_status').addClass('hidden');
      $('#change_priority').addClass('hidden');
    };
  }; 

  app.appMod = function() {
    if (app.applyType.val() == 'existing') {
      app.application.removeClass('hidden');
      $('#current_status_label').removeClass('hidden');
    } else if (app.applyType.val() == 'both') {
      app.application.removeClass('hidden');
      $('#current_status_label').removeClass('hidden');
    } else if (app.applyType.val() == 'incoming') {
      app.application.addClass('hidden');
      $('#current_status_label').addClass('hidden');
    }
  }
  
  // bind events
  app.table.on('click', 'tr', app.startTrack);
  app.nav.on('click', '.minerva-filters', app.FilterChanges);
  app.changeType.change(app.formMod);
  app.actionType.change(app.actionMod); 
  app.applyType.change(app.appMod);
  $('#minerva-applyFilter').click(app.addFilter);
  
})(jQuery, minerva.filters);
