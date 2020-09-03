import unittest
from copy import deepcopy

import tictactoe as ttt

X = ttt.X
O = ttt.O
EMPTY = ttt.EMPTY

# define some reusable boards
_empty_board = [
    [EMPTY,    EMPTY,  EMPTY],
    [EMPTY,    EMPTY,  EMPTY],
    [EMPTY,    EMPTY,  EMPTY]
]
_X_turn1 = [
    [X,       O,      EMPTY],
    [EMPTY,   EMPTY,  EMPTY],
    [EMPTY,   EMPTY,  EMPTY]
]
_X_turn2 = [
    [X,       X,      O],
    [EMPTY,   O,      EMPTY],
    [EMPTY,   EMPTY,  EMPTY]
]
_X_turn3 = [
    [X,       X,      O],
    [O,       O,      EMPTY],
    [X,       EMPTY,  EMPTY]
]
_O_turn1 = [
    [X,       EMPTY,  EMPTY],
    [EMPTY,   EMPTY,  EMPTY],
    [EMPTY,   EMPTY,  EMPTY]
]
_O_turn2 = [
    [X,       X,      O],
    [EMPTY,   EMPTY,  EMPTY],
    [EMPTY,   EMPTY,  EMPTY]
]
_O_turn3 = [
    [X,       X,      O],
    [EMPTY,   O,      EMPTY],
    [X,       EMPTY,  EMPTY]
]
_terminated_tie1 = [
    [X,        O,      X],
    [X,        X,      O],
    [O,        X,      O]
]
_terminated_tie2 = [
    [O,       X,      O],
    [X,       O,      X],
    [X,       O,      X]
]
_terminated_tie3 = [
    [O,       X,      X],
    [X,       O,      O],
    [O,       X,      X]
]
_terminated_winner_X1 = [
    [X,       X,      X],
    [EMPTY,   O,      EMPTY],
    [EMPTY,   EMPTY,  O]
]
_terminated_winner_X2 = [
    [X,       EMPTY,  EMPTY],
    [X,       O,      EMPTY],
    [X,       EMPTY,  O]
]
_terminated_winner_X3 = [
    [X,       O,      O],
    [EMPTY,   X,      EMPTY],
    [EMPTY,   EMPTY,  X]
]
_terminated_winner_X4 = [
    [EMPTY,   EMPTY,  EMPTY],
    [X,       X,      X],
    [EMPTY,   O,      O]
]
_terminated_winner_X5 = [
    [EMPTY,   X,  O],
    [EMPTY,   X,  EMPTY],
    [EMPTY,   X,  O]
]
_terminated_winner_X6 = [
    [EMPTY,   O,      X],
    [EMPTY,   X,      EMPTY],
    [X,       EMPTY,  O]
]
_terminated_winner_O1 = [
    [O,       O,      O],
    [X,       X,      EMPTY],
    [EMPTY,   EMPTY,  X]
]
_terminated_winner_O2 = [
    [O,       X,      X],
    [O,       X,      EMPTY],
    [O,       EMPTY,  EMPTY]
]
_terminated_winner_O3 = [
    [O,       X,      X],
    [EMPTY,   O,      X],
    [EMPTY,   EMPTY,  O]
]
_in_progress1 = [
    [O,       O,      EMPTY],
    [X,       X,      EMPTY],
    [EMPTY,   EMPTY,  X]
]
_in_progress2 = [
    [O,       X,      X],
    [O,       X,      EMPTY],
    [EMPTY,   EMPTY,  EMPTY]
]
_in_progress3 = [
    [O,       X,      X],
    [EMPTY,   O,      X],
    [EMPTY,   EMPTY,  EMPTY]
]

class PlayerTestCase(unittest.TestCase):
    
    def test_initial_board(self):
        board = _empty_board
        result = ttt.player(board)
        self.assertEqual(result, X)

    def test_next_player_is_X(self):
        boards=[_X_turn1, _X_turn2, _X_turn3]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.player(board)
                self.assertEqual(result, X)

    def test_next_player_is_O(self):
        boards=[_O_turn1, _O_turn2, _O_turn3]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.player(board)
                self.assertEqual(result, O)

# End class


class ActionsTestCase(unittest.TestCase):

    def test_empty_board(self):
        board = _empty_board
        result = ttt.actions(board)
        expected = set([
                (0,0),  (0,1),  (0,2),
                (1,0),  (1,1),  (1,2),
                (2,0),  (2,1),  (2,2),
        ])
        self.assertSetEqual(result, expected)

    def test_eight_actions(self):
        board = [[X,        EMPTY,  EMPTY],
                 [EMPTY,    EMPTY,  EMPTY],
                 [EMPTY,    EMPTY,  EMPTY]]
        result = ttt.actions(board)
        expected = set([
                        (0,1),  (0,2),
                (1,0),  (1,1),  (1,2),
                (2,0),  (2,1),  (2,2),
        ])
        self.assertSetEqual(result, expected)

    def test_five_actions(self):
        board = [[X,        O,      X],
                 [EMPTY,    EMPTY,  EMPTY],
                 [EMPTY,    EMPTY,  O]]
        result = ttt.actions(board)
        expected = set([
                
                (1,0),  (1,1),  (1,2),
                (2,0),  (2,1)
        ])
        self.assertSetEqual(result, expected)

    def test_no_actions(self):
        boards=[_terminated_tie1, _terminated_tie2, _terminated_tie3]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.actions(board)
                expected = set([])
                self.assertSetEqual(result, expected)

# End class


class ResultTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.board = deepcopy(_O_turn1)
    
    def test_action_raises_exception(self):
        board = self.board.copy()
        action = (0,0)
        with self.assertRaises(ValueError):
            ttt.result(board, action)

    def test_action_raises_no_exception(self):
        board = self.board.copy()
        action = (1,1)
        try:
            result = ttt.result(board, action)
        except ValueError:
            self.fail("ttt.result() raised ValueError unexpectedly!")

    def test_results(self):
        board = self.board.copy()
        actions = [
                   (0,1), (0,2), 
            (1,0), (1,1), (1,2),
            (2,0), (2,1), (2,2),
        ]
        expected_boards = []
        for action in actions:
            (i, j) = action 
            brd = deepcopy(board)
            brd[i][j] = O
            expected_boards.append(brd)

        for action, expected_board in zip(actions, expected_boards):
            with self.subTest(action=action, expected_board=expected_board):
                result = ttt.result(board, action)
                self.assertListEqual(expected_board, result)

# End class


class WinnerTestCase(unittest.TestCase):

    def test_winner_is_X(self):
        boards=[_terminated_winner_X1, _terminated_winner_X2, _terminated_winner_X3, 
                _terminated_winner_X4, _terminated_winner_X5, _terminated_winner_X6]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.winner(board)
                self.assertEqual(result, X)

    def test_winner_is_O(self):
        boards=[_terminated_winner_O1, _terminated_winner_O2, _terminated_winner_O3]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.winner(board)
                self.assertEqual(result, O)

    def test_game_in_progress(self):
        boards=[_in_progress1, _in_progress2, _in_progress3]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.winner(board)
                self.assertIsNone(result)

    def test_tie(self):
        boards=[_terminated_tie1, _terminated_tie2, _terminated_tie3]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.winner(board)
                self.assertIsNone(result)

# End class


class TerminalTestCase(unittest.TestCase):

    def test_game_is_over_tie(self):
        boards=[_terminated_tie1, _terminated_tie2, _terminated_tie3]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.terminal(board)
                self.assertTrue(result)

    def test_game_is_over_X_won(self):
        boards=[_terminated_winner_X1, _terminated_winner_X2, _terminated_winner_X3, 
                _terminated_winner_X4, _terminated_winner_X5, _terminated_winner_X6]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.terminal(board)
                self.assertTrue(result)

    def test_game_is_over_O_won(self):
        boards=[_terminated_winner_O1, _terminated_winner_O2, _terminated_winner_O3]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.terminal(board)
                self.assertTrue(result)

    def test_game_is_in_progress(self):
        boards=[_in_progress1, _in_progress2, _in_progress3]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.terminal(board)
                self.assertFalse(result)

# End class


class UtilityTestCase(unittest.TestCase):
    
    def test_winner_is_X(self):
        boards=[_terminated_winner_X1, _terminated_winner_X2, _terminated_winner_X3, 
                _terminated_winner_X4, _terminated_winner_X5, _terminated_winner_X6]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.utility(board)
                self.assertEqual(result, 1)

    def test_winner_is_O(self):
        boards=[_terminated_winner_O1, _terminated_winner_O2, _terminated_winner_O3]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.utility(board)
                self.assertEqual(result, -1)

    def test_game_in_progress(self):
        boards=[_in_progress1, _in_progress2, _in_progress3]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.utility(board)
                self.assertEqual(result, 0)

    def test_tie(self):
        boards=[_terminated_tie1, _terminated_tie2, _terminated_tie3]
        for board in boards:
            with self.subTest(board=board):
                result = ttt.utility(board)
                self.assertEqual(result, 0)

# End class


class MinimaxTestCase(unittest.TestCase):
    
    def test_minimax(self):
        boards = [
            [[  X,      X,      EMPTY],
            [   O,      O,      EMPTY],
            [   EMPTY,  EMPTY,  EMPTY]],

            [[  X,      EMPTY,  EMPTY],
            [   EMPTY,  O,      EMPTY],
            [   O,      EMPTY,  X]],

            [[  X,      EMPTY,  O],
            [   EMPTY,  O,      EMPTY],
            [   EMPTY,  EMPTY,  X]],
        ]
        expected_values = [
            (0,2),
            (0,2),
            (2,0),
        ]
        for board, expected in zip(boards, expected_values):
            with self.subTest(board=board, expected=expected):        
                result = ttt.minimax(board)
                self.assertTupleEqual(expected, result)


def suite():
    suite = unittest.TestSuite()
 
    suite.addTest(PlayerTestCase('test_initial_board'))
    suite.addTest(PlayerTestCase('test_next_player_is_X'))
    suite.addTest(PlayerTestCase('test_next_player_is_O'))

    suite.addTest(ActionsTestCase('test_empty_board'))
    suite.addTest(ActionsTestCase('test_eight_actions'))
    suite.addTest(ActionsTestCase('test_five_actions'))
    suite.addTest(ActionsTestCase('test_no_actions'))

    suite.addTest(ResultTestCase('test_action_raises_exception'))
    suite.addTest(ResultTestCase('test_action_raises_no_exception'))
    suite.addTest(ResultTestCase('test_results'))

    suite.addTest(WinnerTestCase('test_winner_is_X'))
    suite.addTest(WinnerTestCase('test_winner_is_O'))
    suite.addTest(WinnerTestCase('test_game_in_progress'))
    suite.addTest(WinnerTestCase('test_tie'))

    suite.addTest(TerminalTestCase('test_game_is_over_tie'))
    suite.addTest(TerminalTestCase('test_game_is_over_X_won'))
    suite.addTest(TerminalTestCase('test_game_is_over_O_won'))
    suite.addTest(TerminalTestCase('test_game_is_in_progress'))

    suite.addTest(UtilityTestCase('test_winner_is_X'))
    suite.addTest(UtilityTestCase('test_winner_is_O'))
    suite.addTest(UtilityTestCase('test_game_in_progress'))
    suite.addTest(UtilityTestCase('test_tie'))

    suite.addTest(MinimaxTestCase('test_minimax'))
    
    return suite

if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
