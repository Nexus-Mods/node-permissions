const fs = require('fs');
const path = require('path');

let winAcl = (() => {
  let lib;
  return () => {
    if (lib === undefined) {
      lib = require('nbind').init(path.join(__dirname)).lib;
    }
    return lib;
  }
})();

function chmodTranslateRight(user, input) {
  let base = [
    ['x', 1],
    ['w', 2],
    ['r', 4]
  ].reduce((prev, perm) => input.indexOf(perm[0]) !== -1 ? prev + perm[2] : prev);

  switch (user) {
    case 'everyone': return base * 73; // 7 -> 0777
    case 'owner': return base * 64;    // 7 -> 0700
    case 'group': return base * 8;     // 7 -> 0070
    case 'guest': return base;         // 7 -> 0007
    default: return 0;    // 0
  }
}

function chmod(target, user, rights) {
  return new Promise((resolve, reject) => {
    fs.stat(target, (statErr, stats) => {
      if (statErr !== null) {
        reject(statErr);
      } else {
        const chmod = (addRights) => {
          fs.chmod(target, stats.mode | addRights, chmodErr => {
            return chmodErr !== null ?
              reject(chmodErr) :
              resolve();
          });
        }
        let addRight = chmodTranslateRight(user, rights);
        if (addRight === 0) {
          fs.chown(target, fs.userInfo().uid, fs.userInfo().gid, (chownError) => {
            chmod(chmodTranslateRight('owner', rights));
          });
        } else {
          chmod(addRight);
        }
      }
    });
  });
}

function allow(target, user, rights) {
  if (process.platform === 'win32') {
    try {
      winAcl().apply(winAcl().Access.grant(user, rights), target);
      return chmod(target, user, rights);
    } catch (err) {
      return Promise.reject(err);
    }
  } else {
    return chmod(target, user, rights);
  }
}

function getUserId() {
  if (process.platform === 'win32') {
    return winAcl().getSid();
  } else {
    return os.userInfo().username;
  }
}

module.exports = {
  allow,
  getUserId,
};
