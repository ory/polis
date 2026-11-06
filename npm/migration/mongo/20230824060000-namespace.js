module.exports = {
  async up(db, client) {
        const collection = db.collection('jacksonStore');
        const response = await collection.distinct('_id', {});
        const searchTerm = ':';
        for (const k in response) {
          const key = response[k].toString();
          const tokens2 = key.split(searchTerm).slice(0, 2);
          const value = tokens2.join(searchTerm); 
          await db.collection('jacksonStore').updateOne({ _id: key }, {$set: { namespace: value }});
        }

  },

  async down(db, client) {
    const collection = db.collection('jacksonStore');
    const response = await collection.distinct('_id', {});
    for (const k in response) {
      const key = response[k].toString();
      await db.collection('jacksonStore').updateOne({ _id: key }, {$set: { namespace: '' }});
    }
  }
};
