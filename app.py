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
storage = {
    'rooms': {},
    'users': {},
    'tokens': {}
}


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
