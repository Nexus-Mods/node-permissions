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
  ].reduce((prev, perm) => input.indexOf(perm[0]) !== -1 ? prev + perm[1] : prev, 0);

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
        return reject(statErr);
      }

      const chmodInner = (addRights) => {
        fs.chmod(target, (stats.mode & 0777) | addRights, chmodErr => {
          return chmodErr !== null ?
            reject(chmodErr) :
            resolve();
        });
      }
      let addRight = chmodTranslateRight(user, rights);
      if (addRight === 0) {
        // specific user, so we need to change the owner. Except we can't do that on windows with chown
        if (process.platform === 'win32') {
          chmodInner(chmodTranslateRight('owner', rights));
        } else {
          fs.chown(target, parseInt(user, 10), stats.gid, (chownError) => {
            chmodInner(chmodTranslateRight('owner', rights));
          });
        }
      } else {
        chmodInner(addRight);
      }
      return resolve();
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
