
if(typeof console != "object") {
  window.console = {
      log: function(l) {}
  };
}

$(document).ready(function() {
  game = new TicTacToe();
  
});

function TicTacToe(opts) {
  var self = this;
  $.extend(self, opts || {});
  self.init();
}

TicTacToe.prototype = {
  game_opcode: {
    SET_NAME: 0,
    MAKE_MOVE: 1,
    SET_READY: 2,
    LIST_PLAYERS: 3,
    GAME_START: 4,
    BOARD_STATE: 5,
    NOTIFY_LETTER: 6,
    GAME_STATE: 7,
    NAME_CHANGED: 8,
    GAME_WON: 9
  },
  
  letter_constants: ["&nbsp;", "X", "O"],
  
  game_state: {
    STOPPED: 0,
    RUNNING: 1
  },
  
  $player_list: null,
  $gameboard: null,
  $game_state: null,
  ws: null,
  board_spaces: null,
  myletter: null,
  myname: null,
  requested_name: null,
  player_ready: null,

  drawBoard: function() {
    var self = this;
    self.$gameboard.html("<table/>");
    var $table = self.$gameboard.find("table");
    for(var i=0;i<3;i++) {
      var $row = $("<tr/>");
      for(var x=0;x<3;x++) {
        var idx = 3*i + x;
        var val = self.board_spaces[idx];
        if(val == 0) { var xoro = "&nbsp;"; }
        if(val == 1) { var xoro = "X"; }
        if(val == 2) { var xoro = "O"; }
        $row.append("<td><div class='big' data-idx='" + idx + "'>" + xoro + "</div></td>");
      }
      $table.append($row);
    }
    $table.find('td').css("padding", "20px");
    $table.find('td').css("border", "1px solid black");
    $table.find('td').css("backgroundColor", "#f0f0f0");
    $table.css("backgroundColor", "#000");
    $table.css("borderSpacing", "0px");
    $table.find('.big').css("fontSize", "20pt");
    $table.find('.big').css("width", "60px");
    $table.find('.big').css("height", "60px");
    $table.css("cursor", "pointer");
  },
  
  handleClick: function(e) {
    var self = this;
    var idx = typeof $(e.target).find('.big').data("idx") == "undefined" ? $(e.target).data("idx") : $(e.target).find(".big").data("idx");
    self.ws.send(self.game_opcode.MAKE_MOVE + "::" + idx);
  },
  
  init: function() {
    var self = this;
    self.myname = "";
    self.$player_list = $("#player_list");
    self.$gameboard = $("#gameboard");
    self.$game_state = $("#game_state");
    self.board_spaces = [0,0,0,0,0,0,0,0,0];
    self.player_ready = false;
    self.ws = new WebSocket("ws://192.168.0.50:8080");
    self.ws.onclose = function(e) {
      self.onclose(e);
    };
    self.ws.onopen = function(e) {
      self.onopen(e);
    };
    self.ws.onerror = function(e) {
      self.onerror(e);
    };
    self.ws.onmessage = function(e) {
      self.onmessage(e);
    };
    self.drawBoard();
    self.$gameboard.on("click", "td", function(e) {
      self.handleClick(e);
    });
    
  },
  
  onclose: function(e) {
    if(e.code == 1006) {
      alert("Unable to connect to WebSockets server.");
    }
    
  },
  
  onerror: function(e) {
    console.log(e);
  },
  
  onmessage: function(e) {
    var self = this;
    var data = e.data;
    if(!data.length) { console.log("Empty frame received"); }
    var sdata = data.split("::");
    var opcode = parseInt(sdata[0], 10);
    var game_data = sdata[1];
    switch(opcode) {
      case self.game_opcode.GAME_WON:
        self.ws.send(self.game_opcode.GAME_STATE + "::querystate");
        alert(game_data + " wins the game!");
        for(var i=0;i<self.board_spaces.length;i++) {
          self.board_spaces[i] = 0;
        }
        self.drawBoard();
        break;
      case self.game_opcode.GAME_START:
        self.ws.send(self.game_opcode.GAME_STATE + "::querystate");
        break;
      case self.game_opcode.NAME_CHANGED:
        self.ws.send(self.game_opcode.LIST_PLAYERS + "::players");
        break;
      case self.game_opcode.GAME_STATE:
        var state = parseInt(game_data, 10);
        if(state == self.game_state.STOPPED) {
          self.$game_state.html("Game is: STOPPED");
        } else if(state == self.game_state.RUNNING) {
          self.$game_state.html("Game is: RUNNING");
        }
        break;
      case self.game_opcode.SET_NAME:
        if(game_data != "success") {
          console.log("Problem setting name.");
        } else {
          self.myname = self.requested_name;
        }
        self.ws.send(self.game_opcode.LIST_PLAYERS + "::getplayers");
        break;
      case self.game_opcode.BOARD_STATE:
        var new_state = game_data.split(",");
        if(new_state.length != 9) {
          console.log("Problem getting game state.");
          return false;
        }
        self.board_spaces = new_state;
        self.drawBoard();
        break;
      case self.game_opcode.LIST_PLAYERS:
        var players = game_data.split(",");
        var $ul = $('<ul/>');
        $.each(players, function(idx, player) {
          if(player == self.myname) {
            $ul.append('<li><strong>' + player + '</strong></li>');
          } else {
            $ul.append('<li>' + player + '</li>');
          }
        });
        self.$player_list.html('');
        self.$player_list.append($ul);
        break;
      case self.game_opcode.NOTIFY_LETTER:
        self.myletter = self.letter_constants[parseInt(game_data, 10)];
        break;
      default:
        console.log("Unknown opcode in data: " + data);
    }
  },
  
  onopen: function(e) {
    var self = this;
    var name = null;
    while(name == null) {
      name = prompt("What is your name?");
    }
    self.requested_name = name;
    self.ws.send(self.game_opcode.SET_NAME + "::" + name);
    self.ws.send(self.game_opcode.GAME_STATE + "::querystate");
  }
}
