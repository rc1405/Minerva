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

minerva.config = {};

(function ($, app) {
  // declare module properties
  app.nav = $('nav');
  app.csrf_token = $('#csrf_token').val();

  app.saveConfig = function() {
    var data = {};
    $.each($('form').serializeArray(), function(i, item) {
      data[item.name] = item.value;
    });
    $.ajax({
      method: 'POST',
      url: '/config',
      data: JSON.stringify(data),
      contentType: 'application/json',
      headers: {
        csrfmiddlewaretoken: app.csrf_token
      },
      success: function (data) {
        alert(data);
        location="/config";
      },
    });
  };

  // bind events
  //
  app.nav.on('click', '.minerva-saveConf', app.saveConfig);

})(jQuery, minerva.config);
