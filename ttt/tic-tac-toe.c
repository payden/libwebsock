#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <websock/websock.h>

#include "ttt.h"


ttt_game *game;
int winning_moves[8] = {7, 56, 73, 84, 146, 273, 292, 448};


int connect_callback(libwebsock_client_state *state) {
	char buf[1024];
	player *newPlayer = NULL;
	if(game->num_players < 2) {
		fprintf(stderr, "Less than two players, accepting new player.\n");
		newPlayer = (player *)malloc(sizeof(player));
		memset(newPlayer, 0, sizeof(player));
		newPlayer->sockfd = state->sockfd;
		if(game->player1 == NULL) {
			newPlayer->letter = LETTER_X;
			game->player1 = newPlayer;
		} else {
			newPlayer->letter = LETTER_O;
			game->player2 = newPlayer;
		}
		state->data = newPlayer;
		game->num_players++;
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf)-1, "%d::%d", NOTIFY_LETTER, newPlayer->letter);
		libwebsock_send_text(state->sockfd, buf);
	}
	return 0;
}

int close_callback(libwebsock_client_state *state) {
	int i;
	player *leavingPlayer = (player *)state->data;
	if(leavingPlayer != NULL && (leavingPlayer == game->player1 || leavingPlayer == game->player2)) {
		if(leavingPlayer == game->player1) {
			if(game->player1->name != NULL) {
				free(game->player1->name);
			}
			free(game->player1);
			game->player1 = NULL;
		}
		if(leavingPlayer == game->player2) {
			if(game->player2->name != NULL) {
				free(game->player2->name);
			}
			free(game->player2);
			game->player2 = NULL;
		}
		game->num_players--;
		game->state = STOPPED;
		for(i=0;i<9;i++)
			game->board[i] = NULL;
	}
	return 0;
}

int receive_callback(libwebsock_client_state *state, libwebsock_message *msg) {
	int i;
	enum game_opcode g_opcode;
	player *currentPlayer = NULL, *otherPlayer = NULL;
	char buf[1024];
	char *game_data = (char *)malloc(msg->payload_len);
	if(!game_data) {
		fprintf(stderr, "Error allocating memory in receive_callback.. exiting.\n");
		exit(1);
	}
	sscanf(msg->payload, "%d::%s", (int *)&g_opcode, game_data);
	currentPlayer = (player *)state->data;

	if(game->player1 != state->data && game->player2 != state->data) {
		fprintf(stderr, "Received a message from a non-player.\n");
		return 0;
	}
	if(game->player1 == currentPlayer) {
		otherPlayer = game->player2;
	} else {
		otherPlayer = game->player1;
	}

	switch(g_opcode) {
		case GAME_STATE:
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf)-1, "%d::%d", g_opcode, game->state);
			libwebsock_send_text(currentPlayer->sockfd, buf);
			break;
		case MAKE_MOVE:
			memset(buf, 0, sizeof(buf));
			if(game->state == STOPPED) {
				snprintf(buf, sizeof(buf)-1, "%d::gamestopped", g_opcode);
				libwebsock_send_text(currentPlayer->sockfd, buf);
			} else {
				if((game->turn == PLAYER1 && currentPlayer == game->player1) || (game->turn == PLAYER2 && currentPlayer == game->player2)) {
					sscanf(game_data, "%d", &i);
					if(game->board[i] != NULL) {
						snprintf(buf, sizeof(buf)-1, "%d::spaceoccupied", g_opcode);
						libwebsock_send_text(currentPlayer->sockfd, buf);
					} else {
						game->board[i] = currentPlayer;
						currentPlayer->moves |= 1 << i;
						send_board_update();
						if(currentPlayer == game->player1) {
							game->turn = PLAYER2;
						} else {
							game->turn = PLAYER1;
						}
						if(check_game_won(currentPlayer) == 1) {
							for(i=0;i<9;i++) {
								game->board[i] = NULL;
							}
							snprintf(buf, sizeof(buf)-1, "%d::%s", GAME_WON, currentPlayer->name);
							libwebsock_send_text(game->player1->sockfd, buf);
							libwebsock_send_text(game->player2->sockfd, buf);
							break;
						}

					}
				} else {
					snprintf(buf, sizeof(buf)-1, "%d::notyourturn", g_opcode);
					libwebsock_send_text(currentPlayer->sockfd, buf);
				}
			}
			break;
		case SET_NAME:
			currentPlayer->name = (char *)malloc(strlen(game_data) + 1);
			if(!currentPlayer->name) {
				fprintf(stderr, "couldn't allocate memory.\n");
				exit(1);
			}
			memset(currentPlayer->name, 0, strlen(game_data) + 1);
			strncpy(currentPlayer->name, game_data, strlen(game_data));
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf)-1, "%d::success", g_opcode);
			libwebsock_send_text(state->sockfd, buf);
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf)-1, "%d::namechanged", NAME_CHANGED);
			if(otherPlayer != NULL) {
				libwebsock_send_text(otherPlayer->sockfd, buf);
			}
			libwebsock_send_text(currentPlayer->sockfd, buf);
			if(game->player1 != NULL && game->player1->name != NULL && game->player2 != NULL && game->player2->name != NULL) {
				startGame();
			}
			break;
		case SET_READY:
			currentPlayer->ready = 1;
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf)-1, "%d::success", g_opcode);
			libwebsock_send_text(currentPlayer->sockfd, buf);
			if(currentPlayer->ready == 1 && otherPlayer->ready == 1 && game->state == STOPPED) {
				startGame();
			}
			break;
		case LIST_PLAYERS:
			i = 0;
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf)-1, "%d::", g_opcode);
			if(game->player1 != NULL && game->player1->name != NULL) {
				strcat(buf, game->player1->name);
				i = 1;
			}
			if(game->player2 != NULL && game->player2->name != NULL) {
				if(i == 1) {
					strcat(buf, ",");
				}
				strcat(buf, game->player2->name);
			}
			libwebsock_send_text(currentPlayer->sockfd, buf);
			break;
		case BOARD_STATE:
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf)-1, "%d::", g_opcode);
			if(game->board[0] == NULL) {
				strcat(buf, "0");
			} else if(game->board[0] == game->player1) {
				strcat(buf, "1");
			} else {
				strcat(buf, "2");
			}
			for(i=1;i<9;i++) {
				if(game->board[i] == NULL) {
					strcat(buf, ",0");
				} else if(game->board[i] == game->player1) {
					strcat(buf, ",1");
				} else {
					strcat(buf, ",2");
				}
			}
			libwebsock_send_text(currentPlayer->sockfd, buf);
			break;
		default:
			break;
	}
	return 0;
}

void startGame() {
	char buf[1024];
	if(game->player1 == NULL || game->player2 == NULL) {
		fprintf(stderr, "Refusing to start game without both players.\n");
		return;
	}
	game->turn = PLAYER1;
	game->state = RUNNING;
	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf)-1, "%d::start", GAME_START);
	libwebsock_send_text(game->player1->sockfd, buf);
	libwebsock_send_text(game->player2->sockfd, buf);
}

void send_board_update() {
	int i;
	char buf[1024];
	enum game_opcode g_opcode = BOARD_STATE;
	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf)-1, "%d::", g_opcode);
	if(game->board[0] == NULL) {
		strcat(buf, "0");
	} else if(game->board[0] == game->player1) {
		strcat(buf, "1");
	} else {
		strcat(buf, "2");
	}
	for(i=1;i<9;i++) {
		if(game->board[i] == NULL) {
			strcat(buf, ",0");
		} else if(game->board[i] == game->player1) {
			strcat(buf, ",1");
		} else {
			strcat(buf, ",2");
		}
	}
	libwebsock_send_text(game->player1->sockfd, buf);
	libwebsock_send_text(game->player2->sockfd, buf);
}

int check_game_won(player *p) {
	int i;
	fprintf(stderr, "Player %d moves: %d\n", p == game->player1 ? 1 : 2, p->moves);
	for(i=0;i<8;i++) {
		fprintf(stderr, "Winning movies %d: %d ANDED: %d\n", i, winning_moves[i], p->moves & winning_moves[i]);
		if((p->moves & winning_moves[i]) == winning_moves[i]) {
			return 1;
		}
	}
	return 0;
}

int main(int argc, char **argv) {
	game = (ttt_game *)malloc(sizeof(ttt_game));
	memset(game, 0, sizeof(ttt_game));
	game->state = STOPPED;
	libwebsock_context *ctx = NULL;
	ctx = libwebsock_init("8080");
	libwebsock_set_close_cb(ctx, &close_callback);
	libwebsock_set_connect_cb(ctx, &connect_callback);
	libwebsock_set_receive_cb(ctx, &receive_callback);
	libwebsock_wait(ctx);
	return 0;
}
