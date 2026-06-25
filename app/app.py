from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, Response
from werkzeug.utils import secure_filename
import ftplib
import uuid
import time
import json
from flask_login import LoginManager
from scheduler import init_scheduler, validate_interval_string
from functools import wraps
from file_watcher import Watcher
import threading
import logging
import sys
import copy
import flask.cli
from datetime import timedelta
flask.cli.show_server_banner = lambda *args: None
from constants import *
from settings import *
from db import *
from shop import *
from auth import *
import titles as titles_lib
from utils import *
from library import *
import titledb
import os
import re
from clients import CyberFoilClient, TinfoilClient, SphairaClient

_transfer_progress = {}
_transfer_lock = threading.Lock()

def init():
    global watcher
    global watcher_thread
    # Create and start the file watcher
    logger.info('Initializing File Watcher...')
    watcher = Watcher(on_library_change)
    watcher_thread = threading.Thread(target=watcher.run)
    watcher_thread.daemon = True
    watcher_thread.start()

    # Load initial configuration
    logger.info('Loading initial configuration...')
    reload_conf()

    # init libraries
    library_paths = app_settings['library']['paths']
    init_libraries(app, watcher, library_paths)

    # Initialize and schedule jobs
    logger.info('Initializing Scheduler...')
    init_scheduler(app)
    scan_interval_str = app_settings.get('scheduler', {}).get('scan_interval', '12h')
    schedule_update_and_scan_job(app, scan_interval_str, run_first=True, run_once=True)

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

## Global variables
app_settings = {}
watcher = None
watcher_thread = None
# Create a global variable and lock for scan_in_progress
scan_in_progress = False
scan_lock = threading.Lock()
# Global flag for titledb update status
is_titledb_update_running = False
titledb_update_lock = threading.Lock()

# Configure logging
formatter = ColoredFormatter(
    '[%(asctime)s.%(msecs)03d] %(levelname)s (%(module)s) %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(formatter)

logging.basicConfig(
    level=logging.INFO,
    handlers=[handler]
)

# Create main logger
logger = logging.getLogger('main')
logger.setLevel(logging.DEBUG)

# Apply filter to hide date from http access logs
logging.getLogger('werkzeug').addFilter(FilterRemoveDateFromWerkzeugLogs())

# Suppress specific Alembic INFO logs
logging.getLogger('alembic.runtime.migration').setLevel(logging.WARNING)

@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.filter_by(id=user_id).first()

def reload_conf():
    global app_settings
    global watcher
    app_settings = load_settings()

def on_library_change(events):
    # TODO refactor: group modified and created together
    with app.app_context():
        created_events = [e for e in events if e.type == 'created']
        modified_events = [e for e in events if e.type != 'created']

        for event in modified_events:
            if event.type == 'moved':
                if file_exists_in_db(event.src_path):
                    # update the path
                    update_file_path(event.directory, event.src_path, event.dest_path)
                else:
                    # add to the database
                    event.src_path = event.dest_path
                    created_events.append(event)

            elif event.type == 'deleted':
                # delete the file from library if it exists
                delete_file_by_filepath(event.src_path)

            elif event.type == 'modified':
                # can happen if file copy has started before the app was running
                add_files_to_library(event.directory, [event.src_path])

        if created_events:
            directories = list(set(e.directory for e in created_events))
            for library_path in directories:
                new_files = [e.src_path for e in created_events if e.directory == library_path]
                add_files_to_library(library_path, new_files)

    post_library_change()

def create_app():
    app = Flask(__name__)
    app.url_map.strict_slashes = False  # Disable automatic trailing slash redirects globally, needed for Sphaira
    app.config["SQLALCHEMY_DATABASE_URI"] = OWNFOIL_DB
    # TODO: generate random secret_key
    app.config['SECRET_KEY'] = '8accb915665f11dfa15c2db1a4e8026905f57716'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    app.register_blueprint(auth_blueprint)

    return app

# Create app
app = create_app()

# List of supported client classes
SUPPORTED_CLIENTS = [CyberFoilClient, TinfoilClient, SphairaClient]


def get_client_for_request(request):
    """Identify and return the appropriate client for the request, or None if no client matches."""
    reload_conf()
    for client_class in SUPPORTED_CLIENTS:
        if client_class.identify_client(request):
            return client_class(app_settings)
    return None

def file_access(f):
    """Decorator for file serving endpoints with basic authentication (no client identification required)."""
    @wraps(f)
    def _file_access(*args, **kwargs):
        reload_conf()

        # Check if shop is private
        if not app_settings['shop']['public']:
            # Shop is private, require authentication
            auth_success, auth_error, user = basic_auth(request)
            if not auth_success:
                return jsonify({'error': auth_error}), 401
            elif not user.has_shop_access():
                return jsonify({'error': f'User "{user.user}" does not have access to the shop.'}), 403

        return f(*args, **kwargs)
    return _file_access

def access_shop():
    return render_template('index.html', title='Library', admin_account_created=admin_account_created())

@access_required('shop')
def access_shop_auth():
    return access_shop()

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path=None):
    """Main shop endpoint routing to either client-specific shop or web browser UI."""
    # Check if this is a client request
    client = get_client_for_request(request)

    if client:
        # Check if client is enabled
        client_name = client.CLIENT_NAME.lower()
        client_settings = app_settings.get('shop', {}).get('clients', {}).get(client_name, {})
        if not client_settings.get('enabled', False):
            logger.warning(f"{client.CLIENT_NAME} connection from {request.remote_addr} - Client is disabled")
            return client.error_response(f"Shop access from {client.CLIENT_NAME} is disabled.")
        
        # Handle client request
        logger.info(f"{client.CLIENT_NAME} connection from {request.remote_addr}")
        return client.handle_request(request)

    # Browser request - serve web UI
    elif path:
        return redirect('/')

    if not app_settings['shop']['public']:
        return access_shop_auth()
    return access_shop()

@app.route('/settings')
@access_required('admin')
def settings_page():
    with open(os.path.join(TITLEDB_DIR, 'languages.json')) as f:
        languages = json.load(f)
        languages = dict(sorted(languages.items()))
    return render_template(
        'settings.html',
        title='Settings',
        languages_from_titledb=languages,
        admin_account_created=admin_account_created())

@app.route('/setup')
def setup_page():
    """Setup page showing client information and connection instructions."""
    reload_conf()
    
    # Check if user has access (must have shop access or shop must be public)
    if not app_settings['shop']['public'] and admin_account_created():
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not current_user.has_shop_access():
            return 'Forbidden', 403

    local_address = None
    local_port  = None
    
    # Get remote host from configuration
    remote_host = app_settings['shop'].get('host', '')
    
    # Check if we're accessing via the configured remote host
    # If so, hide the local tab since we're already remote
    show_local_tab = remote_host and (remote_host != request.host)
    if show_local_tab:
        local_address = request.host.split(':')[0]
        local_port = request.host.split(':')[1] if ':' in request.host else 80
    
    # Check if clients are enabled
    tinfoil_enabled = app_settings.get('shop', {}).get('clients', {}).get('tinfoil', {}).get('enabled', False)
    sphaira_enabled = app_settings.get('shop', {}).get('clients', {}).get('sphaira', {}).get('enabled', False)
    cyberfoil_enabled = app_settings.get('shop', {}).get('clients', {}).get('cyberfoil', {}).get('enabled', False)
    
    # Check if shop is public
    shop_public = app_settings['shop']['public']
    
    return render_template(
        'setup.html',
        title='Setup',
        local_address=local_address,
        local_port=local_port,
        remote_host=remote_host,
        show_local_tab=show_local_tab,
        tinfoil_enabled=tinfoil_enabled,
        sphaira_enabled=sphaira_enabled,
        cyberfoil_enabled=cyberfoil_enabled,
        shop_public=shop_public,
        admin_account_created=admin_account_created()
    )

@app.get('/api/settings')
@access_required('admin')
def get_settings_api():
    reload_conf()
    settings = copy.deepcopy(app_settings)
    # Strip hauth values for privacy (don't send to client)
    if 'clients' in settings['shop']:
        for client_name, client_settings in settings['shop']['clients'].items():
            if 'hauth' in client_settings:
                # Replace hauth dict with empty dict to keep it private
                settings['shop']['clients'][client_name]['hauth'] = {}
    return jsonify(settings)

@app.post('/api/settings/titles')
@access_required('admin')
def set_titles_settings_api():
    reload_conf()
    title_settings = request.json
    region = title_settings['region']
    language = title_settings['language']
    with open(os.path.join(TITLEDB_DIR, 'languages.json')) as f:
        languages = json.load(f)
        languages = dict(sorted(languages.items()))

    if region not in languages or language not in languages[region]:
        resp = {
            'success': False,
            'errors': [{
                    'path': 'titles',
                    'error': f"The region/language pair {region}/{language} is not available."
                }]
        }
        return jsonify(resp)

    if region != app_settings['titles']['region'] or language != app_settings['titles']['language']:
        set_titles_settings(region, language)
        reload_conf()
        titledb.update_titledb(app_settings)
        post_library_change()

    resp = {
        'success': True,
        'errors': []
    } 
    return jsonify(resp)

@app.post('/api/settings/shop')
@access_required('admin')
def set_shop_settings_api():
    data = request.json
    set_shop_settings(data)
    reload_conf()
    resp = {
        'success': True,
        'errors': []
    } 
    return jsonify(resp)

@app.route('/api/settings/library/paths', methods=['GET', 'POST', 'DELETE'])
@access_required('admin')
def library_paths_api():
    global watcher
    if request.method == 'POST':
        data = request.json
        success, errors = add_library_complete(app, watcher, data['path'])
        if success:
            reload_conf()
            post_library_change()
        resp = {
            'success': success,
            'errors': errors
        }
    elif request.method == 'GET':
        reload_conf()
        resp = {
            'success': True,
            'errors': [],
            'paths': app_settings['library']['paths']
        }
    elif request.method == 'DELETE':
        data = request.json
        success, errors = remove_library_complete(app, watcher, data['path'])
        if success:
            reload_conf()
            post_library_change()
        resp = {
            'success': success,
            'errors': errors
        }
    return jsonify(resp)

@app.post('/api/settings/library/management')
@access_required('admin')
def set_library_management_settings_api():
    data = request.json
    set_library_management_settings(data)
    reload_conf()
    post_library_change()
    resp = {
        'success': True,
        'errors': []
    }
    return jsonify(resp)

@app.post('/api/settings/scheduler')
@access_required('admin')
def set_scheduler_settings_api():
    data = request.json
    scan_interval_str = data.get('scan_interval')

    if scan_interval_str is not None:
        is_valid, error_msg = validate_interval_string(scan_interval_str)
        if not is_valid:
            return jsonify({
                'success': False,
                'errors': [{'path': 'scheduler/scan_interval', 'error': error_msg}]
            })

    set_scheduler_settings(data)
    reload_conf()

    if scan_interval_str is not None:
        try:
            current_interval_str = app_settings.get('scheduler', {}).get('scan_interval', '12h')
            schedule_update_and_scan_job(app, current_interval_str, run_first=False)
        except Exception as e:
            logger.error(f"Error updating scheduler: {e}")
            return jsonify({
                'success': False,
                'errors': [{'path': 'scheduler', 'error': str(e)}]
            })

    return jsonify({'success': True, 'errors': []})

@app.post('/api/upload')
@access_required('admin')
def upload_file():
    errors = []
    success = False
    valid_keys = None
    try:
        file = request.files['file']
        if file and allowed_file(file.filename):
            # filename = secure_filename(file.filename)
            file.save(KEYS_FILE)
            logger.info(f'Validating {file.filename}...')
            valid_keys, missing_keys, corrupt_keys = load_keys(KEYS_FILE)
            if valid_keys:
                post_library_change()
            else:
                logger.warning(f'Invalid keys from {file.filename}')
            success = True
            logger.info('Successfully saved keys.txt')

    except Exception as e:
        logger.error(f'Failed to upload console keys file: {e}')
        os.remove(KEYS_FILE)
        success = False
        errors.append(str(e))

    resp = {
        'success': success,
        'errors': errors,
        'data': {}
    }

    if valid_keys is not None:
        resp['data']['valid_keys'] = valid_keys
        resp['data']['missing_keys'] = missing_keys
        resp['data']['corrupt_keys'] = corrupt_keys

    return jsonify(resp)


@app.route('/upload')
@access_required('upload')
def upload_page():
    app_settings = load_settings()
    library_paths = app_settings['library']['paths']
    return render_template(
        'upload.html',
        title='Upload',
        library_paths=library_paths,
        admin_account_created=admin_account_created()
    )

@app.post('/api/library/upload')
@access_required('upload')
def upload_game_files():
    errors = []
    saved = []

    dest_path = request.form.get('library_path', '')
    app_settings = load_settings()
    valid_paths = app_settings['library']['paths']

    if dest_path not in valid_paths:
        return jsonify({'success': False, 'errors': ['Invalid library path'], 'saved': []})

    files = request.files.getlist('files')
    if not files:
        return jsonify({'success': False, 'errors': ['No files provided'], 'saved': []})

    for file in files:
        if not file.filename:
            continue
        ext = file.filename.rsplit('.', 1)[-1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            errors.append(f'{file.filename}: unsupported file type')
            continue
        filename = secure_filename(file.filename)
        save_path = os.path.join(dest_path, filename)
        try:
            file.save(save_path)
            saved.append(filename)
            logger.info(f'Uploaded game file: {save_path}')
        except Exception as e:
            errors.append(f'{filename}: {e}')
            logger.error(f'Failed to save uploaded file {filename}: {e}')

    if saved:
        post_library_change()

    return jsonify({'success': len(saved) > 0, 'errors': errors, 'saved': saved})


@app.route('/send-to')
@access_required('admin')
def send_to_page():
    app_settings = load_settings()
    send_to_cfg = app_settings.get('send_to', {})
    files = db.session.query(
        Files.id, Files.filename, Files.size, Files.extension, Files.identified
    ).order_by(Files.filename).all()
    files_list = [{'id': f.id, 'filename': f.filename, 'size': f.size, 'extension': f.extension, 'identified': f.identified} for f in files]
    return render_template(
        'send_to.html',
        title='Send To',
        send_to=send_to_cfg,
        files=files_list,
        admin_account_created=admin_account_created()
    )

@app.post('/api/settings/send-to')
@access_required('admin')
def set_send_to_settings_api():
    data = request.json
    try:
        set_send_to_settings({
            'host': data.get('host', ''),
            'port': int(data.get('port', 21)),
            'username': data.get('username', ''),
            'password': data.get('password', ''),
        })
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f'Failed to save send_to settings: {e}')
        return jsonify({'success': False, 'error': str(e)})

@app.post('/api/send-to/send')
@access_required('admin')
def send_to_switch():
    data = request.json
    file_id = data.get('file_id')
    if not file_id:
        return jsonify({'success': False, 'error': 'No file_id provided'})

    file_row = db.session.query(Files.filepath, Files.filename).filter_by(id=file_id).first()
    if not file_row:
        return jsonify({'success': False, 'error': 'File not found'})

    filepath, filename = file_row.filepath, file_row.filename
    app_settings = load_settings()
    cfg = app_settings.get('send_to', {})
    host = cfg.get('host', '')
    port = int(cfg.get('port', 21))
    username = cfg.get('username', '') or 'anonymous'
    password = cfg.get('password', '') or ''

    if not host:
        return jsonify({'success': False, 'error': 'Switch host not configured'})

    transfer_id = str(uuid.uuid4())
    with _transfer_lock:
        _transfer_progress[transfer_id] = {'progress': 0, 'done': False, 'error': None}

    def do_ftp():
        try:
            file_size = os.path.getsize(filepath)
            sent = [0]

            def ftp_callback(block):
                sent[0] += len(block)
                pct = int(sent[0] / file_size * 100) if file_size else 100
                with _transfer_lock:
                    _transfer_progress[transfer_id]['progress'] = pct

            with ftplib.FTP() as ftp:
                ftp.connect(host, port, timeout=30)
                ftp.login(username, password)
                with open(filepath, 'rb') as f:
                    ftp.storbinary(f'STOR {filename}', f, callback=ftp_callback)
            logger.info(f'Sent {filename} to Switch at {host}:{port}')
            with _transfer_lock:
                _transfer_progress[transfer_id]['progress'] = 100
                _transfer_progress[transfer_id]['done'] = True
        except Exception as e:
            logger.error(f'FTP send failed for {filename}: {e}')
            with _transfer_lock:
                _transfer_progress[transfer_id]['error'] = str(e)
                _transfer_progress[transfer_id]['done'] = True

    threading.Thread(target=do_ftp, daemon=True).start()
    return jsonify({'success': True, 'transfer_id': transfer_id})

@app.get('/api/send-to/progress/<transfer_id>')
@access_required('admin')
def send_to_progress(transfer_id):
    def generate():
        while True:
            with _transfer_lock:
                state = _transfer_progress.get(transfer_id)
            if state is None:
                yield f'data: {json.dumps({"progress": 0, "done": True, "error": "Transfer not found"})}\n\n'
                break
            yield f'data: {json.dumps({"progress": state["progress"], "done": state["done"], "error": state["error"]})}\n\n'
            if state['done']:
                with _transfer_lock:
                    _transfer_progress.pop(transfer_id, None)
                break
            time.sleep(0.5)

    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
    })


@app.route('/api/titles', methods=['GET'])
@access_required('shop')
def get_all_titles_api():
    titles_library = generate_library()

    return jsonify({
        'total': len(titles_library),
        'games': titles_library,
        'hash': compute_apps_hash(),
    })


@app.get('/api/library/hash')
@access_required('shop')
def get_library_hash_api():
    return jsonify({'hash': compute_apps_hash()})

@app.route('/api/get_game/<int:id>')
@file_access
def serve_game(id):
    """Serve a game file to authenticated clients."""
    filepath = db.session.query(Files.filepath).filter_by(id=id).first()[0]
    filedir, filename = os.path.split(filepath)
    increment_download_count_throttled(filepath, request.remote_addr)
    return send_from_directory(filedir, filename)


@debounce(10, key='post_library_change')
def post_library_change():
    with app.app_context():
        titles_lib.load_titledb()
        process_library_identification(app)
        add_missing_apps_to_db()
        # remove missing files
        remove_missing_files_from_db()
        update_titles() # Ensure titles are updated after identification
        process_library_organization(app, watcher) # Pass the watcher instance to skip organizer move/delete events
        # The process_library_identification already handles updating titles and generating library
        # So, we just need to ensure titles_library is updated from the generated library
        generate_library()
        titles_lib.identification_in_progress_count -= 1
        titles_lib.unload_titledb()

def _strip_id_tags(filename):
    """Remove [APPID] and [vVERSION] tags from a filename stem, leaving everything else intact."""
    stem, ext = os.path.splitext(filename)
    stem = re.sub(r'\s*\[[0-9A-Fa-f]{16}\]', '', stem)
    stem = re.sub(r'\s*\[v\d+\]', '', stem)
    return stem.strip() + ext

@app.post('/api/library/rescan-file/<int:file_id>')
@access_required('admin')
def rescan_file_api(file_id):
    try:
        file_obj = Files.query.filter_by(id=file_id).first()
        if not file_obj:
            return jsonify({'success': False, 'error': 'File not found'}), 404
        if not os.path.exists(file_obj.filepath):
            return jsonify({'success': False, 'error': 'File no longer exists on disk'}), 400

        # Block the background watcher from competing during the entire reset+scan window
        titles_lib.identification_in_progress_count += 1
        try:
            # 1. Delete all title/app records for this game — clean slate
            ok, err = full_reset_file_and_title(file_id)
            if not ok:
                return jsonify({'success': False, 'error': err}), 500

            # Re-fetch after commit so we have a live ORM object with updated state
            file_obj = Files.query.filter_by(id=file_id).first()

            # 2. Strip [appid][version] tags from the filename so the CNMT fallback
            #    can't lock in the wrong type from the old filename metadata
            new_filename = _strip_id_tags(file_obj.filename)
            if new_filename != file_obj.filename:
                new_filepath = os.path.join(os.path.dirname(file_obj.filepath), new_filename)
                try:
                    os.rename(file_obj.filepath, new_filepath)
                    old_name = file_obj.filename
                    file_obj.filename = new_filename
                    file_obj.filepath = new_filepath
                    db.session.commit()
                    logger.info(f'Renamed for rescan: {old_name!r} → {new_filename!r}')
                except OSError as rename_err:
                    logger.warning(f'Could not rename {file_obj.filename}: {rename_err} — proceeding without rename')

            # 3. Fresh identification — load_titledb increments the counter again;
            #    its finally block decrements it, leaving our outer +1 still active
            #    until the outer finally runs.
            titles_lib.load_titledb()
            try:
                ok, err = rescan_file_in_library(file_id)
                add_missing_apps_to_db()
                update_titles()
                generate_library()
            finally:
                titles_lib.identification_in_progress_count -= 1  # balances load_titledb
                titles_lib.unload_titledb()

        finally:
            titles_lib.identification_in_progress_count -= 1  # balances our initial block

        if not ok:
            return jsonify({'success': False, 'error': err}), 500

        logger.info(f'Rescan complete for file id={file_id} ({file_obj.filename})')
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f'Unexpected error in rescan_file_api for file_id={file_id}: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500


@app.post('/api/library/scan')
@access_required('admin')
def scan_library_api():
    data = request.json
    path = data['path']
    success = True
    errors = []

    global scan_in_progress
    with scan_lock:
        if scan_in_progress:
            logger.info('Skipping scan_library_api call: Scan already in progress')
            return {'success': False, 'errors': []}
    # Set the scan status to in progress
    scan_in_progress = True

    try:
        if path is None:
            scan_library()
        else:
            scan_library_path(path)
    except Exception as e:
        errors.append(e)
        success = False
        logger.error(f"Error during library scan: {e}")
    finally:
        with scan_lock:
            scan_in_progress = False

    post_library_change()
    resp = {
        'success': success,
        'errors': errors
    }
    return jsonify(resp)


@app.get('/api/library/files')
@access_required('admin')
def get_library_files_api():
    files = Files.query.options(
        db.joinedload(Files.apps).joinedload(Apps.title)
    ).order_by(Files.filename).all()

    result = []
    for f in files:
        contents = [
            {
                'app_id': app.app_id,
                'app_type': app.app_type,
                'app_version': app.app_version,
                'title_id': app.title.title_id if app.title else None,
            }
            for app in f.apps
        ]
        result.append({
            'id': f.id,
            'filename': f.filename,
            'size': f.size,
            'extension': f.extension,
            'identified': f.identified,
            'identification_type': f.identification_type,
            'identification_error': f.identification_error,
            'multicontent': f.multicontent,
            'contents': contents,
        })

    return jsonify({'files': result})


# @app.before_request
# def before_request():
#     # print request headers for debugging
#     logger.debug(f"Incoming request: {request.method} {request.path}")
#     for header, value in request.headers:
#         logger.debug(f"Header: {header} = {value}")

def scan_library():
    logger.info(f'Scanning whole library ...')
    libraries = get_libraries()
    for library in libraries:
        scan_library_path(library.path) # Only scan, identification will be done globally

def update_and_scan_job():
    """Combined job: updates TitleDB then scans library"""
    logger.info("Running update job (TitleDB update and library scan)...")
    global scan_in_progress
    
    # Update TitleDB with locking
    with titledb_update_lock:
        is_titledb_update_running = True
    
    logger.info("Starting TitleDB update...")
    try:
        settings = load_settings()
        titledb.update_titledb(settings)
        logger.info("TitleDB update completed.")
    except Exception as e:
        logger.error(f"Error during TitleDB update: {e}")
    finally:
        with titledb_update_lock:
            is_titledb_update_running = False
    
    # Check if update is still running before scanning
    with titledb_update_lock:
        if is_titledb_update_running:
            logger.info("Skipping library scan: TitleDB update still in progress.")
            return
    
    # Scan library with locking
    logger.info("Starting library scan...")
    with scan_lock:
        if scan_in_progress:
            logger.info('Skipping library scan: scan already in progress.')
            return
        scan_in_progress = True
    
    try:
        scan_library()
        post_library_change()
        logger.info("Library scan completed.")
    except Exception as e:
        logger.error(f"Error during library scan: {e}")
    finally:
        with scan_lock:
            scan_in_progress = False
    
    logger.info("Update job completed.")

def schedule_update_and_scan_job(app: Flask, interval_str: str, run_first: bool = True, run_once: bool = False):
    """Schedule or update the update_and_scan job"""
    app.scheduler.update_job_interval(
        job_id='update_db_and_scan',
        interval_str=interval_str,
        func=update_and_scan_job,
        run_first=run_first,
        run_once=run_once
    )


if __name__ == '__main__':
    logger.info('Starting initialization of Ownfoil...')
    init_db(app)
    init_users(app)
    init()
    logger.info('Initialization steps done, starting server...')
    app.run(debug=False, use_reloader=False, host="0.0.0.0", port=8465)
    # Shutdown server
    logger.info('Shutting down server...')
    watcher.stop()
    watcher_thread.join()
    logger.debug('Watcher thread terminated.')
    # Shutdown scheduler
    app.scheduler.shutdown()
    logger.debug('Scheduler terminated.')
