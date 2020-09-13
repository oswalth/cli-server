import tornado.ioloop
import tornado.web
import asyncio
import tornado
import json
import hashlib
import uuid
import secrets
import platform
import os

MESSAGE_LIMIT = 128
# storage = {
#     'rooms': {},
#     'users': {},
#     'tokens': {}
# }
storage = {'rooms': {'testroom1': {'users': {'WE1y1ivozdZKBXHt76iPBnvZJo3sZ1OUYHcCBSwDo6k': 'not_oswalth'}, 'messages': []}}, 'users': {'oswalth': {'salt': 'fb6ff7b1dcfa4d4881f47a0ffebf30ac',
                                                                                                                                                    'key': 'f3faefb66ce9709c60c7865ff2bc09ab7f7c7a743bc5d5c7ba88293f65de22e8e561ab4e402783bf44c83d2cf839e30f03663612a1c770a6b53a72ff96fb5383', 'token': 'WE1y1ivozdZKBXHt76iPBnvZJo3sZ1OUYHcCBSwDo6k'}}, 'tokens': {'WE1y1ivozdZKBXHt76iPBnvZJo3sZ1OUYHcCBSwDo6k': 'oswalth'}}

# storage = {'rooms': {'testroom': {'users': {'yrrxfZRASDn8-rH4glzvaeyxeFek7OplgdEOO9KtjVE': 'oswalth'}, 'messages': []}}, 'users': {'oswalth': {'salt': '44529692a1a143a5be4e81f26d529469',
#                                                                                                                                                'key': 'fd3c2a846fa908b282b591aadc5a05e61f623fe8f5665e5fb5fdb3eda55300d561a072cf6d27014b72d8694403d51b05584008059a2daacb1512421adb59c452', 'token': 'yrrxfZRASDn8-rH4glzvaeyxeFek7OplgdEOO9KtjVE'}}, 'tokens': {'yrrxfZRASDn8-rH4glzvaeyxeFek7OplgdEOO9KtjVE': 'oswalth'}}


class NewRoomHandle(tornado.web.RequestHandler):
    def post(self):
        data = (json.loads(self.request.body))
        roomname = data['roomname']
        token = data['token']
        username = data.get('username', None) or storage['tokens'][token]
        if storage['rooms'].get(roomname, None) is None:
            print('Имя не занято')
            storage['rooms'][roomname] = {
                'users': {token: username}, 'messages': []}
        else:
            print('Имя занято')
            self.write({'message': 'Имя занято'})
        print(storage)


class SubscribeHandle(tornado.web.RequestHandler):
    def post(self):
        data = (json.loads(self.request.body))
        roomname = data['roomname']
        token = data['token']
        username = data.get('username', None) or storage['tokens'][token]
        room = storage['rooms'].get(roomname, None)
        if room is None:
            self.set_status(400)
            self.write({'message': 'Room not found'})
        else:
            if not username in room['users'].values():
                room['users'][token] = username
                print(f'{username} has joined room {roomname}')
                self.write({'messages': room['messages']})
            else:
                self.set_status(400)
                self.write({'message': 'Username is occupied'})


class RoomHandle(tornado.web.RequestHandler):
    def post(self):
        data = (json.loads(self.request.body))
        roomname = data['roomname']
        token = data['token']
        room = storage['rooms'].get(roomname, None)
        if room is None:
            self.set_status(400)
            self.write({'message': 'Room not found'})
        else:
            if not token in room['users']:
                self.set_status(400)
                self.write(
                    {'message': 'Subscribe first to see room\'s history '})
            else:
                self.write({'messages': room['messages']})


class RegisterHandle(tornado.web.RequestHandler):
    def post(self):
        data = (json.loads(self.request.body))
        if data['username'] in storage['users']:
            print('ЗАНЯТА НАХУЙ')
            self.set_status(400)
            self.write({'message': 'Username is occupied'})
        else:
            salt = uuid.uuid4().hex
            key = hashlib.sha512(
                str(data['password']).encode('utf-8') + salt.encode('utf-8')).hexdigest()
            token = secrets.token_urlsafe()

            storage['users'][data['username']] = {
                'salt': salt,
                'key': key,
                'token': token
            }
            storage['tokens'][token] = data['username']
        print(storage)


def get_key(username, password, salt):
    return hashlib.sha512(
        str(password).encode('utf-8') + salt.encode('utf-8')).hexdigest()


class LoginHandle(tornado.web.RequestHandler):
    def post(self):
        data = (json.loads(self.request.body))
        user = data['username']
        password = data['password']

        if storage['users'].get(user, None):
            key = get_key(user, password, storage['users'][user]['salt'])
            is_password_correct = key == storage['users'][user]['key']
        else:
            self.set_status(400)
            self.write({'message': 'User not found'})
            return

        if data['username'] not in storage['users'] or not is_password_correct:
            self.set_status(400)
            self.write({'message': 'Username or password is incorrect'})
        else:
            self.write({'token': storage['users'][user]['token']})
        print(storage)


class PublishHandle(tornado.web.RequestHandler):
    def post(self):
        data = (json.loads(self.request.body))
        message = data['message']
        token = data['token']
        roomname = data['roomname']
        room = storage['rooms'][roomname]
        if len(room['messages']) == MESSAGE_LIMIT:
            room['messages'].pop(0)
        room['messages'].append(
            {'sender': room['users'][token], 'text': message})


def make_app():
    return tornado.web.Application([
        (r"/newroom", NewRoomHandle),
        (r"/subscribe", SubscribeHandle),
        (r"/publish", PublishHandle),
        (r"/register", RegisterHandle),
        (r"/login", LoginHandle),
        (r"/room", RoomHandle),
    ])


if __name__ == "__main__":
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    app = make_app()
    app.listen(address='0.0.0.0', port=os.environ.get('PORT', 5000))
    tornado.ioloop.IOLoop.current().start()
