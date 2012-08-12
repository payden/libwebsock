/*
 * ttt.h
 *
 *  Created on: Aug 1, 2012
 *      Author: payden
 */

#ifndef TTT_H_
#define TTT_H_

#define LETTER_BLANK 0
#define LETTER_X 1
#define LETTER_O 2

enum ttt_turn {PLAYER1, PLAYER2};
enum ttt_state {STOPPED, RUNNING};
enum game_opcode {SET_NAME, MAKE_MOVE, SET_READY, LIST_PLAYERS, GAME_START, BOARD_STATE, NOTIFY_LETTER, GAME_STATE, NAME_CHANGED, GAME_WON};

typedef struct _player {
	int sockfd;
	int ready;
	int letter;
	int moves;
	char *name;
} player;

typedef struct _ttt_game {
	enum ttt_state state;
	int num_players;
	struct _player *player1;
	struct _player *player2;
	struct _player *board[9];
	enum ttt_turn turn;
} ttt_game;


void send_board_update();
void startGame();

#endif /* TTT_H_ */
