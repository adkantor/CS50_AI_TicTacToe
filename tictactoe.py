"""
Tic Tac Toe Player
"""

import math
from copy import deepcopy

X = "X"
O = "O"
EMPTY = None


def initial_state():
    """
    Returns starting state of the board.
    """
    return [[EMPTY, EMPTY, EMPTY],
            [EMPTY, EMPTY, EMPTY],
            [EMPTY, EMPTY, EMPTY]]


def player(board):
    """
    Returns player who has the next turn on a board.

    @param board        board state
    @ return            X or O
    """    
    # In the initial game state, X gets the first move
    if board == initial_state():
        return X

    # Count Xs and Os
    cnt_X = sum(x.count(X) for x in board)
    cnt_O = sum(x.count(O) for x in board)
    # if equal -> X is the next player, else Y
    if cnt_X == cnt_O:
        return X
    else:
        return O

def actions(board):
    """
    Returns set of all possible actions (i, j) available on the board.

    @param board        board state
    @return             set of actions represented as a tuple(i,j) where i,j represent row and col indexes
    """    
    # possible action = empty cells -> put them into the set
    empty_cells = set()
    for i, j in [(i, j) for i in range(3) for j in range(3)]:
        if board[i][j] == EMPTY:
            empty_cells.add((i, j))

    return empty_cells


def result(board, action):
    """
    Returns the board that results from making move (i, j) on the board.

    @param board        board state
    @param action       action as tuple(i,j) where i,j represent row and col indexes
    @return             new board state
    """    
    new_board = deepcopy(board)
    i = action[0]
    j = action[1]

    # check whether action is valid
    if not board[i][j] == EMPTY:
        raise ValueError(f'Invalid action ({i}, {j})')
    
    # put player's sign into the cell marked by (i,j)
    p = player(board)
    new_board[i][j] = p

    return new_board


def winner(board):
    """
    Returns the winner of the game, if there is one.

    @param board        board state
    @return             X or O or None
    """    
    # check by row
    for i in range(3):
        if (board[i][0] == board[i][1] == board[i][2] != None):
            return board[i][0]
    # check by column
    for j in range(3):
        if (board[0][j] == board[1][j] == board[2][j] != None):
            return board[0][j]
    # check diagonals
        if (board[0][0] == board[1][1] == board[2][2]  != None or \
            board[2][0] == board[1][1] == board[0][2] != None):
            return board[1][1]

    return None


def terminal(board):
    """
    Returns True if game is over, False otherwise.

    @param board        board state
    @return             True/False
    """
    # check if game has been won or there is no possible actions left
    return (winner(board) is not None or len(actions(board)) == 0)


def utility(board):
    """
    Returns 1 if X has won the game, -1 if O has won, 0 otherwise.
 
    @param board        board state
    @return             1, -1 or 0
    """
    lookup = {X: 1, O:-1, None:0}
    return lookup[winner(board)]


def minimax(board):
    """
    Returns the optimal action for the current player on the board.

    @param board        board state
    @return             action as tuple(i,j) where i,j represent row and col indexes
    """
    # check if board is terminal
    if terminal(board):
        return None

    # initialize alpha and beta for pruning
    # inspired by:
    # https://www.geeksforgeeks.org/minimax-algorithm-in-game-theory-set-4-alpha-beta-pruning/
    alpha, beta = -1000, 1000

    # get allowable actions
    allowable_actions = list(actions(board))

    # player X plays goes for max
    if player(board) == X:
        values = [min_value(result(board, a), alpha, beta) for a in allowable_actions]
        v = max(values)
    # player O goes for min
    else:
        values = [max_value(result(board, a), alpha, beta) for a in allowable_actions]
        v = min(values)
        
    # get action based on value v
    ndx = values.index(v) # index of highest / lowest value
    optimal_action = allowable_actions[ndx]

    return optimal_action

    
def max_value(board, alpha, beta):
    """
    Returns higest value of possible actions of a board.
    """
    if terminal(board):
        return utility(board)

    v = -1000
    for action in actions(board):
        v = max(v, min_value(result(board, action), alpha, beta))
        alpha = max(alpha, v)
        if alpha >= beta:
            break
    
    return v


def min_value(board, alpha, beta):
    """
    Returns lowest value of possible actions of a board.
    """
    if terminal(board):
        return utility(board)

    v = 1000
    for action in actions(board):
        v = min(v, max_value(result(board, action), alpha, beta))
        beta = min(beta, v)
        if alpha >= beta:
            break
    
    return v
