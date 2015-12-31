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

minerva.watchlist = {};

(function ($, app) {
  // declare module properties
  app.selected = [];  
  app.nav = $('nav');
  app.table = $('#event_table tbody');
  app.application = $('#current_status');
  //app.form_type = $('#form_type').val();
  app.csrf_token = $('#csrf_token').val();
  app.watchType = $('#watchlist_select');
  app.inputMethod = $('#input_method');
  
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

  app.WatchlistChanges = function(e) {
    var action = $(e.target).data('action');

    if (app.selected.length) {

      var data = {
        events: app.selected,
        req_type: action,
      };

      $.ajax({
        method: 'POST',
        url: '/watchlist_json',
        data: JSON.stringify(data),
        contentType: 'application/json',
        headers: {
          csrfmiddlewaretoken: app.csrf_token
        },
        success: function (response) {
          if (response != 'None') {
            alert(response);
          };
          location='/watchlist';
        },
      });
    } else {
      alert('No Items selected');
    };
  };
  
  app.addWatchlist = function() {
    var data = {
         'type': $('#watchlist_select').val(),
         'req_type': 'new',
         'priority': $('#priority').val(),
         'tag': $('#tag').val(),
    }
    if (app.inputMethod.val() == 'file') {
         data['input_type'] = 'file';
         data['watchlist_file'] = $('watchlist_file').files;
    } else {
         data['input_type'] = 'individual';
         data['criteria'] = $('#watchlist_item').val();
    };
    if ($('#disable_old').prop('checked')) {
      data['disable_old'] = 'yes';
    } else {
      data['disable_old'] = 'no';
    }; 
    $.ajax({
      method: 'POST',
      url: '/watchlist',
      data: JSON.stringify(data),
      contentType: 'application/json',
      headers: {
        csrfmiddlewaretoken: app.csrf_token
      },
      success: function (response) {
        if (response) {
          alert(response);
        };
        location='/watchlist';
      },
    });
  };

  app.formMod = function() {
    if (app.watchType.val() == 'ip_address') {
      $('#criteria_label').text('IP Address/CIDR Range');
    } else if (app.watchType.val() == 'domain') {
      $('#criteria_label').text('Domain Name');
    }
  }

  app.typeMod = function() {
    if (app.inputMethod.val() == 'file') {
      app.application.removeClass('hidden');
      $('#criteria_div').addClass('hidden');
      $('#file_div').removeClass('hidden');
      $('#disable_div').removeClass('hidden');
    } else if (app.inputMethod.val() == 'individual') {
      $('#criteria_div').removeClass('hidden');
      $('#file_div').addClass('hidden');
      $('#disable_div').addClass('hidden');
    }
  }


  // bind events
  app.table.on('click', 'tr', app.startTrack);
  app.nav.on('click', '.minerva-watchlist', app.WatchlistChanges);
  app.watchType.change(app.formMod);
  app.inputMethod.change(app.typeMod);
  //$('#minerva-addWatchlist').click(app.addWatchlist);
  
})(jQuery, minerva.watchlist);
